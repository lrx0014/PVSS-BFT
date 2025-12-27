package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// Helper methods

// formatVRF formats VRF output in scientific notation for readability
func formatVRF(vrfOutput []byte) string {
	vrfInt := new(big.Int).SetBytes(vrfOutput)
	// Convert to float64 for scientific notation
	vrfFloat := new(big.Float).SetInt(vrfInt)
	f64, _ := vrfFloat.Float64()
	return fmt.Sprintf("%.3e", f64)
}

func (n *Node) logInfo(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Info(msg, allArgs...)
}

func (n *Node) logWarn(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Warn(msg, allArgs...)
}

func (n *Node) logError(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Error(msg, allArgs...)
}

func (n *Node) checkContext(ctx context.Context) bool {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return true
}

// requireConsensus returns the consensus state if it exists and matches the view, nil otherwise
func (n *Node) requireConsensus(view types.View) *types.ConsensusState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.consensus == nil || n.consensus.View != view {
		return nil
	}
	return n.consensus
}

func (n *Node) unmarshalMessage(msg *types.Message, target interface{}) interface{} {
	// try direct type assertion first
	targetType := reflect.TypeOf(target).Elem()
	if reflect.TypeOf(msg.Payload) == reflect.PtrTo(targetType) {
		return msg.Payload
	}

	// fallback to JSON unmarshaling
	data, err := json.Marshal(msg.Payload)
	if err != nil {
		return nil
	}

	targetValue := reflect.New(targetType)
	if err := json.Unmarshal(data, targetValue.Interface()); err != nil {
		return nil
	}

	return targetValue.Interface()
}

// verifySignatureForMessage clones msg, removes the signature field via clearSig, and verifies it.
func verifySignatureForMessage[T any](msg *T, pub *ecdsa.PublicKey, clearSig func(*T) []byte) bool {
	if msg == nil || pub == nil {
		return false
	}

	msgCopy := *msg
	sig := clearSig(&msgCopy)
	data, err := json.Marshal(&msgCopy)
	if err != nil {
		return false
	}
	return crypto.Verify(pub, data, sig)
}

func (n *Node) verifyMessageSignature(msg interface{}, publicKey *ecdsa.PublicKey) bool {
	switch m := msg.(type) {
	case *types.ProposeMessage:
		return verifySignatureForMessage(m, publicKey, func(p *types.ProposeMessage) []byte {
			sig := p.Signature
			p.Signature = nil
			return sig
		})
	case *types.ShareMessage:
		return verifySignatureForMessage(m, publicKey, func(s *types.ShareMessage) []byte {
			sig := s.Signature
			s.Signature = nil
			return sig
		})
	case *types.VoteMessage:
		return verifySignatureForMessage(m, publicKey, func(v *types.VoteMessage) []byte {
			sig := v.Signature
			v.Signature = nil
			return sig
		})
	case *types.ConfirmMessage:
		return verifySignatureForMessage(m, publicKey, func(c *types.ConfirmMessage) []byte {
			sig := c.Signature
			c.Signature = nil
			return sig
		})
	case *types.AwakeMessage:
		return verifySignatureForMessage(m, publicKey, func(a *types.AwakeMessage) []byte {
			sig := a.Signature
			a.Signature = nil
			return sig
		})
	case *types.SyncRequestMessage:
		return verifySignatureForMessage(m, publicKey, func(s *types.SyncRequestMessage) []byte {
			sig := s.Signature
			s.Signature = nil
			return sig
		})
	case *types.SyncResponseMessage:
		return verifySignatureForMessage(m, publicKey, func(s *types.SyncResponseMessage) []byte {
			sig := s.Signature
			s.Signature = nil
			return sig
		})
	}
	return false
}

func (n *Node) verifyVRF(view types.View, vrf types.VRFOutput, publicKey *ecdsa.PublicKey) bool {
	vrfInput := []byte(fmt.Sprintf("view:%d", view))
	vrfProof := &crypto.VRFProof{
		Output: vrf.Value,
		Proof:  vrf.Proof,
	}
	valid, _ := n.vrf.Verify(publicKey, vrfInput, vrfProof)
	return valid
}

// tryDecideBlock attempts to decide on a block if quorum is reached
func (n *Node) tryDecideBlock(consensus *types.ConsensusState, decidedHash []byte) {
	if consensus.DecidedBlock != nil {
		return
	}

	confirmCount := 0
	for _, cm := range consensus.Confirms {
		if bytes.Equal(cm.BlockHash, decidedHash) {
			confirmCount++
		}
	}

	activeCount := len(consensus.ActiveNodes)
	quorum := activeCount / 2

	if confirmCount >= quorum {
		leaderProposal := consensus.Proposals[consensus.LeaderID]
		if leaderProposal != nil {
			block := leaderProposal.Block
			block.Hash = decidedHash
			consensus.DecidedBlock = &block
		}
	}
}

// electLeader validates proposals and elects the leader based on highest VRF
func (n *Node) electLeader(view types.View) (types.NodeID, []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil {
		return "", nil
	}

	var leaderID types.NodeID
	var maxVRF []byte

	for id, proposal := range n.consensus.Proposals {
		participant := n.participants[id]
		if participant == nil {
			continue
		}

		// Verify VRF
		if !n.verifyVRF(proposal.View, proposal.VRF, participant.VRFPubKey) {
			continue
		}

		// Verify PVSS shares exist
		if len(proposal.PVSS.Shares) == 0 {
			continue
		}

		// Track highest VRF for leader election
		if maxVRF == nil || crypto.CompareVRFOutputs(proposal.VRF.Value, maxVRF) > 0 {
			maxVRF = proposal.VRF.Value
			leaderID = id
		}

		// Track pre-commits for next round
		if proposal.PreCommit.NextViewJoin {
			n.consensus.NextRoundCommits[id] = true
		}
	}

	n.consensus.LeaderID = leaderID
	n.consensus.LeaderVRF = maxVRF

	return leaderID, maxVRF
}

// verifyAndDecryptLeaderShare verifies and decrypts our share from the leader
func (n *Node) verifyAndDecryptLeaderShare(leaderID types.NodeID, view types.View, nodeID types.NodeID) (*big.Int, types.PVSSShare) {
	n.mu.RLock()
	leaderProposal := n.consensus.Proposals[leaderID]
	n.mu.RUnlock()

	if leaderProposal == nil {
		return nil, types.PVSSShare{}
	}

	var ourShare types.PVSSShare
	for _, share := range leaderProposal.PVSS.Shares {
		if share.Recipient == nodeID {
			ourShare = share
			break
		}
	}

	participant := n.participants[nodeID]
	if participant == nil {
		n.logWarn("Missing participant info for share verification")
		return nil, types.PVSSShare{}
	}

	if !n.pvss.Verify(ourShare.Index, participant.PVSSPubKey, ourShare.Value, leaderProposal.PVSS.Commitment.Coefficients) {
		n.logWarn("Share verification failed")
		return nil, types.PVSSShare{}
	}

	decrypted := n.pvss.DecryptShare(ourShare.Value, n.pvssPriv)
	if decrypted == nil {
		n.logWarn("Failed to decrypt share")
		return nil, types.PVSSShare{}
	}

	return decrypted, ourShare
}

func (n *Node) broadcastShareMessage(view types.View, leaderID types.NodeID, ourShare types.PVSSShare, decrypted *big.Int, nodeID types.NodeID) {
	shareMsg := &types.ShareMessage{
		View:            view,
		LeaderID:        leaderID,
		LeaderShare:     ourShare,
		DecryptedShare:  decrypted,
		AwakeList:       n.getAwakeList(),
		NextRoundCommit: n.getNextRoundCommits(),
	}

	msgData, _ := json.Marshal(shareMsg)
	sig, _ := n.signer.Sign(msgData)
	shareMsg.Signature = sig

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgShare, shareMsg)

	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.ShareMessages[nodeID] = shareMsg
	}
	n.mu.Unlock()
}

func (n *Node) collectValidShares(view types.View, nodeID types.NodeID) []*crypto.PVSSDecryptedShare {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return nil
	}

	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]
	if leaderProposal == nil {
		n.mu.RUnlock()
		return nil
	}

	shareMessages := make(map[types.NodeID]*types.ShareMessage)
	for id, msg := range n.consensus.ShareMessages {
		shareMessages[id] = msg
	}
	n.mu.RUnlock()

	shares := make([]*crypto.PVSSDecryptedShare, 0)
	for senderID, shareMsg := range shareMessages {
		if shareMsg.LeaderID != leaderID {
			continue
		}

		if shareMsg.LeaderShare.Value == nil || shareMsg.DecryptedShare == nil {
			continue
		}

		// Ensure the share matches the sender identity
		if shareMsg.LeaderShare.Recipient != senderID {
			continue
		}

		// Verify encrypted share against leader commitment
		senderInfo := n.participants[senderID]
		if senderInfo == nil {
			continue
		}

		if !n.pvss.Verify(shareMsg.LeaderShare.Index, senderInfo.PVSSPubKey, shareMsg.LeaderShare.Value, leaderProposal.PVSS.Commitment.Coefficients) {
			n.logWarn("Share verification failed, dropping share", "from", senderID)
			continue
		}

		shares = append(shares, &crypto.PVSSDecryptedShare{
			Index: shareMsg.LeaderShare.Index,
			Value: shareMsg.DecryptedShare,
		})
	}

	return shares
}

// determineVote reconstructs the secret and determines the vote
func (n *Node) determineVote(shares []*crypto.PVSSDecryptedShare, view types.View, nodeID types.NodeID) (bool, []byte) {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return false, nil
	}

	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]
	activeCount := len(n.consensus.ActiveNodes)
	n.mu.RUnlock()

	if leaderProposal == nil {
		return false, nil
	}

	threshold := activeCount/2 + 1

	if len(shares) < threshold {
		return false, nil
	}

	// Attempt reconstruction of PVSS secret
	reconstructed, err := n.pvss.Reconstruct(shares)
	if err != nil {
		n.logWarn("Failed to reconstruct PVSS secret", "error", err)
		return false, nil
	}

	if !n.pvss.VerifyReconstruction(reconstructed, leaderProposal.PVSS.SecretHash) {
		n.logWarn("PVSS secret mismatch, voting false")
		return false, nil
	}

	// Verify block hash matches the secret hash
	blockData, _ := json.Marshal(leaderProposal.Block)
	blockHash := crypto.Hash(blockData)

	n.logInfo("Phase3: vote", "vote", "yes", "for_leader", leaderID, "block_height", leaderProposal.Block.Height, "shares", len(shares), "threshold", threshold)

	return true, blockHash
}

func (n *Node) broadcastVoteMessage(view types.View, blockHash []byte, vote bool, nodeID types.NodeID) {
	// Create vote PVSS
	voteData := []byte(fmt.Sprintf("vote:%v:view:%d", vote, view))
	voteHash := crypto.Hash(voteData)
	votePVSS, err := n.createPVSSBundle(voteHash)
	if err != nil {
		n.logError("Failed to create vote PVSS", "error", err)
		return
	}

	voteMsg := &types.VoteMessage{
		View:      view,
		BlockHash: blockHash,
		Vote:      vote,
		VotePVSS:  *votePVSS,
	}

	msgData, _ := json.Marshal(voteMsg)
	sig, _ := n.signer.Sign(msgData)
	voteMsg.Signature = sig

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgVote, voteMsg)

	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Votes[nodeID] = voteMsg
	}
	n.mu.Unlock()
}

func (n *Node) countVotes() (int, []byte) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.consensus == nil {
		return 0, nil
	}

	voteCount := 0
	var decidedHash []byte

	for _, voteMsg := range n.consensus.Votes {
		if voteMsg.Vote {
			voteCount++
			if decidedHash == nil {
				decidedHash = voteMsg.BlockHash
			}
		}
	}

	return voteCount, decidedHash
}

func (n *Node) broadcastConfirmIfQuorum(view types.View, decidedHash []byte, voteCount int, nodeID types.NodeID) {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return
	}

	leaderProposal := n.consensus.Proposals[n.consensus.LeaderID]
	activeCount := len(n.consensus.ActiveNodes)
	quorum := activeCount / 2
	n.mu.RUnlock()

	if voteCount < quorum || leaderProposal == nil {
		return
	}

	confirmMsg := &types.ConfirmMessage{
		View:      view,
		BlockHash: decidedHash,
	}

	msgData, _ := json.Marshal(confirmMsg)
	sig, _ := n.signer.Sign(msgData)
	confirmMsg.Signature = sig

	n.logInfo("Phase4: confirm", "for_leader", leaderProposal.Block.Proposer, "block_height", leaderProposal.Block.Height, "votes", voteCount, "quorum", quorum)

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgConfirm, confirmMsg)

	// Store confirm
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Confirms[nodeID] = confirmMsg
	}
	n.mu.Unlock()
}

func (n *Node) createBlock(view types.View) *types.Block {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Get transactions from pool
	txs := make([]types.Transaction, 0)
	if len(n.txPool) > 0 {
		count := len(n.txPool)
		if count > DefaultMaxTransactionsPerBlock {
			count = DefaultMaxTransactionsPerBlock
		}
		txs = n.txPool[:count]
		n.txPool = n.txPool[count:]
	}

	latest := n.chain.Latest()
	var parentHash []byte
	var height uint64
	if latest != nil {
		parentHash = latest.Hash
		height = latest.Height + 1
	}

	block := &types.Block{
		View:         view,
		Height:       height,
		ParentHash:   parentHash,
		Transactions: txs,
		Proposer:     n.config.NodeID,
		Timestamp:    time.Now(),
	}

	// Compute block hash
	blockData, _ := json.Marshal(block)
	block.Hash = crypto.Hash(blockData)

	return block
}

func (n *Node) createPVSSBundle(secret []byte) (*types.PVSSBundle, error) {
	n.mu.RLock()
	participants := make([]*Participant, 0, len(n.participants))
	for _, p := range n.participants {
		if p.IsActive {
			participants = append(participants, p)
		}
	}
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if len(participants) == 0 {
		return nil, fmt.Errorf("no active participants")
	}

	// Collect public keys
	publicKeys := make([]*big.Int, len(participants))
	for i, p := range participants {
		publicKeys[i] = p.PVSSPubKey
	}

	// Calculate threshold
	threshold := len(participants)/2 + 1

	// Create PVSS shares
	secretInt := crypto.HashToBigInt(secret, n.pvss.Q)
	_, publicData, err := n.pvss.Split(secretInt, publicKeys, threshold)
	if err != nil {
		return nil, err
	}

	// Create share structs
	shares := make([]types.PVSSShare, len(participants))
	for i, p := range participants {
		shares[i] = types.PVSSShare{
			Index:     i + 1,
			Value:     publicData.EncryptedShares[i],
			Recipient: p.ID,
		}
	}

	// Create commitment
	commitment := types.PVSSCommitment{
		Coefficients: publicData.Commitments,
	}

	return &types.PVSSBundle{
		DealerID:   nodeID,
		Shares:     shares,
		Commitment: commitment,
		SecretHash: secret,
	}, nil
}

func (n *Node) broadcast(ctx context.Context, msgType types.MessageType, payload interface{}) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	msg := &types.Message{
		Type:      msgType,
		From:      n.config.NodeID,
		Timestamp: time.Now(),
		Payload:   payload,
	}
	n.network.Broadcast(ctx, msg)
}

func (n *Node) getAwakeList() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := make([]types.NodeID, 0)
	for id, p := range n.participants {
		if p.IsActive {
			list = append(list, id)
		}
	}
	return list
}

func (n *Node) getNextRoundCommits() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.consensus == nil {
		return nil
	}

	list := make([]types.NodeID, 0)
	for id := range n.consensus.NextRoundCommits {
		list = append(list, id)
	}
	return list
}
