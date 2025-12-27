package protocol

import (
	"context"

	"github.com/lrx0014/pvss-bft/pkg/types"
)

// NetworkInterface defines the interface for network communication
type NetworkInterface interface {
	// LocalID returns the local node identifier for the transport.
	LocalID() types.NodeID

	// RegisterHandler registers a handler for a message type
	RegisterHandler(msgType types.MessageType, handler func(msg *types.Message))

	// Start starts the network
	Start(ctx context.Context) error

	// Stop stops the network
	Stop() error

	// AddPeer registers a peer with an optional address
	AddPeer(id types.NodeID, address string) error

	// RemovePeer deregisters a peer.
	RemovePeer(id types.NodeID)

	// Send sends a message to a specific peer.
	Send(ctx context.Context, to types.NodeID, msg *types.Message) error

	// Broadcast sends a message to all peers.
	Broadcast(ctx context.Context, msg *types.Message) error

	// Peers returns the list of known peers.
	Peers() []types.NodeID
}
