package protocol

import (
	"encoding/json"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/types"
)

// synchronizeWithPeers requests missing blocks from peers when waking up
func (n *Node) synchronizeWithPeers() {
	n.mu.RLock()
	myHeight := n.chain.Height()
	ctx := n.ctx
	currentView := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Ask peers about their chain height
	peers := n.network.Peers()
	if len(peers) == 0 {
		n.logWarn("No peers available for synchronization")
		return
	}

	// Request up to 1000 blocks ahead per round
	maxRequestHeight := 1000

	n.logInfo("Starting synchronization", "my_height", myHeight, "current_view", currentView, "requesting_up_to", maxRequestHeight)

	// Request blocks from the first available peer
	for _, peerID := range peers {
		if peerID == nodeID {
			continue
		}

		syncReq := &types.SyncRequestMessage{
			NodeID:      nodeID,
			FromHeight:  myHeight,
			ToHeight:    uint64(maxRequestHeight),
			CurrentView: currentView,
		}

		msgData, _ := json.Marshal(syncReq)
		sig, _ := n.signer.Sign(msgData)
		syncReq.Signature = sig

		n.logInfo("Requesting sync from peer", "peer", peerID, "from_height", myHeight+1, "max_requested_height", maxRequestHeight)

		err := n.network.Send(ctx, peerID, &types.Message{
			Type:      types.MsgSyncRequest,
			From:      nodeID,
			Timestamp: time.Now(),
			Payload:   syncReq,
		})

		if err != nil {
			n.logWarn("Failed to send sync request", "peer", peerID, "error", err)
			continue
		}

		// Only request from one peer at a time to avoid duplicate responses
		break
	}
}
