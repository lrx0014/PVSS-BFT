package protocol

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// startView initializes a new view
func (n *Node) startView(view types.View) {
	n.mu.Lock()

	// Stop previous timers
	if n.viewTimer != nil {
		n.viewTimer.Stop()
	}
	if n.phaseTimer != nil {
		n.phaseTimer.Stop()
	}

	n.currentView = view
	n.consensus = types.NewConsensusState(view)

	// Determine active nodes for this view
	for id, p := range n.participants {
		if p.IsActive {
			n.consensus.ActiveNodes[id] = true
		}
	}

	n.mu.Unlock()

	n.logInfo("Starting view", "view", view, "active_nodes", len(n.consensus.ActiveNodes))

	// Set view timeout
	n.viewTimer = time.AfterFunc(n.config.ViewDuration, func() {
		n.mu.Lock()
		currentView := n.currentView
		n.mu.Unlock()
		if currentView == view {
			n.logWarn("View timeout, advancing to next view", "view", view)
			n.startView(view + 1)
		}
	})

	// Start Phase 1 timer
	n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
		n.advancePhase(types.PhaseShare)
	})

	// Execute Phase 1
	go n.executePhase1()
}

// advancePhase moves to the next phase
func (n *Node) advancePhase(phase types.Phase) {
	n.mu.Lock()
	if n.consensus == nil {
		n.mu.Unlock()
		return
	}
	n.consensus.Phase = phase
	n.mu.Unlock()

	switch phase {
	case types.PhaseShare:
		// Phase 2 timer
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.advancePhase(types.PhaseVote)
		})
		go n.executePhase2()

	case types.PhaseVote:
		// Phase 3 timer
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.advancePhase(types.PhaseConfirm)
		})
		go n.executePhase3()

	case types.PhaseConfirm:
		// Phase 4 timer (also view timer)
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.finalizeView()
		})
		go n.executePhase4()
	}
}

// finalizeView completes the current view and starts the next
func (n *Node) finalizeView() {
	n.mu.Lock()
	currentView := n.currentView
	decidedBlock := n.consensus.DecidedBlock
	n.mu.Unlock()

	if decidedBlock != nil {
		n.chain.Append(decidedBlock)

		n.mu.RLock()
		callback := n.onBlockDecided
		n.mu.RUnlock()

		if callback != nil {
			callback(decidedBlock)
		}
	}

	// next view
	n.startView(currentView + 1)
}

// executePhase1 executes Phase 1: Block Proposal and Share Distribution
func (n *Node) executePhase1() {
	n.mu.RLock()
	if n.state != types.StateAwake {
		n.mu.RUnlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// create a block
	block := n.createBlock(view)

	// pre-commit signal
	preCommit := types.PreCommit{
		NodeID:       nodeID,
		View:         view,
		NextViewJoin: true, // We intend to join next round
	}

	// compute hash of block || precommit
	blockData, _ := json.Marshal(block)
	preCommitData, _ := json.Marshal(preCommit)
	combinedHash := crypto.HashMultiple(blockData, preCommitData)

	// create PVSS shares
	pvssBundle, err := n.createPVSSBundle(combinedHash)
	if err != nil {
		n.logError("Failed to create PVSS bundle", "error", err)
		return
	}

	// generate VRF output
	vrfInput := []byte(fmt.Sprintf("view:%d", view))
	vrfProof, err := n.vrf.Evaluate(n.vrfKey.PrivateKey, vrfInput)
	if err != nil {
		n.logError("Failed to generate VRF", "error", err)
		return
	}

	// create propose message
	proposeMsg := &types.ProposeMessage{
		View:  view,
		Block: *block,
		PVSS:  *pvssBundle,
		VRF: types.VRFOutput{
			Value: vrfProof.Output,
			Proof: vrfProof.Proof,
		},
		PreCommit: preCommit,
	}

	// sign and broadcast
	msgData, _ := json.Marshal(proposeMsg)
	sig, _ := n.signer.Sign(msgData)
	proposeMsg.Signature = sig

	n.logInfo("Phase1: propose", "vrf", formatVRF(vrfProof.Output))

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()
	n.broadcast(broadcastCtx, types.MsgPropose, proposeMsg)

	// store our own proposal
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Proposals[nodeID] = proposeMsg
	}
	n.mu.Unlock()
}

// executePhase2 executes Phase 2: Share Verification and Leader Election
func (n *Node) executePhase2() {
	n.mu.RLock()
	if n.state != types.StateAwake {
		n.mu.RUnlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Elect leader from valid proposals
	leaderID, maxVRF := n.electLeader(view)
	if leaderID == "" {
		n.logWarn("No valid leader found")
		return
	}

	n.logInfo("Phase2: leader elected", "leader", leaderID, "vrf", formatVRF(maxVRF))

	// Verify and decrypt share from the leader
	decryptedShare, ourShare := n.verifyAndDecryptLeaderShare(leaderID, view, nodeID)
	if decryptedShare == nil {
		return
	}

	// Broadcast decrypted share
	n.broadcastShareMessage(view, leaderID, ourShare, decryptedShare, nodeID)
}

// executePhase3 executes Phase 3: Secret Reconstruction and Voting
func (n *Node) executePhase3() {
	n.mu.RLock()
	if n.state != types.StateAwake {
		n.mu.RUnlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Collect and verify shares from other nodes
	shares := n.collectValidShares(view, nodeID)

	// Determine vote based on secret reconstruction
	vote, blockHash := n.determineVote(shares, view, nodeID)

	// Broadcast vote message
	n.broadcastVoteMessage(view, blockHash, vote, nodeID)
}

// executePhase4 executes Phase 4: Confirmation and Consensus
func (n *Node) executePhase4() {
	n.mu.RLock()
	if n.state != types.StateAwake {
		n.mu.RUnlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Count votes and determine if we should send confirmation
	voteCount, decidedHash := n.countVotes()
	if voteCount == 0 || decidedHash == nil {
		return
	}

	// Broadcast confirmation if we have quorum of votes
	n.broadcastConfirmIfQuorum(view, decidedHash, voteCount, nodeID)

	// Check if we can decide on the block
	consensus := n.requireConsensus(view)
	if consensus != nil {
		n.mu.Lock()
		n.tryDecideBlock(consensus, decidedHash)
		n.mu.Unlock()
	}
}
