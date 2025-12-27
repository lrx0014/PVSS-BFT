package protocol

import (
	"encoding/json"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/types"
)

// Message handlers

func (n *Node) handlePropose(msg *types.Message) {
	proposeMsg := n.unmarshalMessage(msg, &types.ProposeMessage{}).(*types.ProposeMessage)
	if proposeMsg == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	// Verify signature
	if !n.verifyMessageSignature(proposeMsg, participant.PublicKey) {
		return
	}

	// Verify VRF output
	if !n.verifyVRF(proposeMsg.View, proposeMsg.VRF, participant.VRFPubKey) {
		return
	}

	// Store proposal
	consensus := n.requireConsensus(proposeMsg.View)
	if consensus == nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	consensus.Proposals[msg.From] = proposeMsg
}

func (n *Node) handleShare(msg *types.Message) {
	shareMsg := n.unmarshalMessage(msg, &types.ShareMessage{}).(*types.ShareMessage)
	if shareMsg == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(shareMsg, participant.PublicKey) {
		return
	}

	consensus := n.requireConsensus(shareMsg.View)
	if consensus == nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	consensus.ShareMessages[msg.From] = shareMsg
	consensus.AwakeLists[msg.From] = shareMsg.AwakeList
}

func (n *Node) handleVote(msg *types.Message) {
	voteMsg := n.unmarshalMessage(msg, &types.VoteMessage{}).(*types.VoteMessage)
	if voteMsg == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(voteMsg, participant.PublicKey) {
		return
	}

	consensus := n.requireConsensus(voteMsg.View)
	if consensus == nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	consensus.Votes[msg.From] = voteMsg
}

func (n *Node) handleConfirm(msg *types.Message) {
	confirmMsg := n.unmarshalMessage(msg, &types.ConfirmMessage{}).(*types.ConfirmMessage)
	if confirmMsg == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(confirmMsg, participant.PublicKey) {
		return
	}

	consensus := n.requireConsensus(confirmMsg.View)
	if consensus == nil {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Store confirm
	consensus.Confirms[msg.From] = confirmMsg

	// Check if we can decide
	n.tryDecideBlock(consensus, confirmMsg.BlockHash)
}

func (n *Node) handleAwake(msg *types.Message) {
	awakeMsg := n.unmarshalMessage(msg, &types.AwakeMessage{}).(*types.AwakeMessage)
	if awakeMsg == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(awakeMsg, participant.PublicKey) {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil {
		return
	}

	// Mark node as newly awake
	n.consensus.NewAwakeNodes[awakeMsg.NodeID] = true
}

func (n *Node) handleSyncRequest(msg *types.Message) {
	syncReq := n.unmarshalMessage(msg, &types.SyncRequestMessage{}).(*types.SyncRequestMessage)
	if syncReq == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(syncReq, participant.PublicKey) {
		return
	}

	n.logInfo("Received sync request", "from", msg.From, "from_height", syncReq.FromHeight, "to_height", syncReq.ToHeight)

	// Get requested blocks
	blocks := n.chain.GetBlockRange(syncReq.FromHeight+1, syncReq.ToHeight)
	if blocks == nil {
		n.logWarn("Cannot provide blocks for sync", "from", msg.From, "from_height", syncReq.FromHeight, "to_height", syncReq.ToHeight)
		return
	}

	// Send sync response
	syncResp := &types.SyncResponseMessage{
		NodeID: n.config.NodeID,
		Blocks: blocks,
	}

	msgData, _ := json.Marshal(syncResp)
	sig, _ := n.signer.Sign(msgData)
	syncResp.Signature = sig

	n.mu.RLock()
	ctx := n.ctx
	n.mu.RUnlock()

	n.logInfo("Sending sync response", "to", msg.From, "blocks_count", len(blocks))
	_ = n.network.Send(ctx, msg.From, &types.Message{
		Type:      types.MsgSyncResponse,
		From:      n.config.NodeID,
		Timestamp: time.Now(),
		Payload:   syncResp,
	})
}

func (n *Node) handleSyncResponse(msg *types.Message) {
	syncResp := n.unmarshalMessage(msg, &types.SyncResponseMessage{}).(*types.SyncResponseMessage)
	if syncResp == nil {
		return
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !n.verifyMessageSignature(syncResp, participant.PublicKey) {
		return
	}

	n.logInfo("Received sync response", "from", msg.From, "blocks_count", len(syncResp.Blocks))

	// Apply blocks to self chain
	for _, block := range syncResp.Blocks {
		// Validate block height is sequential
		expectedHeight := n.chain.Height() + 1
		if block.Height != expectedHeight {
			n.logWarn("Received out-of-order block", "expected", expectedHeight, "got", block.Height)
			continue
		}

		// Add block to chain
		n.chain.Append(block)
		n.logInfo("Synced block", "height", block.Height, "proposer", block.Proposer, "view", block.View)

		// Trigger callback if set
		n.mu.RLock()
		callback := n.onBlockDecided
		n.mu.RUnlock()

		if callback != nil {
			callback(block)
		}
	}

	n.logInfo("Sync completed", "new_height", n.chain.Height())
}
