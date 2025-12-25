package network

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// MessageHandler is called when a message is received
type MessageHandler func(msg *types.Message)

// Network implements the protocol.NetworkInterface interface
var _ protocol.NetworkInterface = (*Network)(nil)

type Network struct {
	mu sync.RWMutex

	nodeID   types.NodeID
	peers    map[types.NodeID]*Peer
	handlers map[types.MessageType][]MessageHandler

	delay time.Duration

	// Message queue for async delivery
	msgQueue chan *deliveryJob

	// Running state
	running bool
	stopCh  chan struct{}
}

// Peer represents a connected peer in the network
type Peer struct {
	ID      types.NodeID
	Address string
	Network *Network // Reference to its network
}

// deliveryJob represents a message to be delivered
type deliveryJob struct {
	to  types.NodeID
	msg *types.Message
}

func NewNetwork(nodeID types.NodeID) *Network {
	n := &Network{
		nodeID:   nodeID,
		peers:    make(map[types.NodeID]*Peer),
		handlers: make(map[types.MessageType][]MessageHandler),
		delay:    0,
		msgQueue: make(chan *deliveryJob, 10000),
		stopCh:   make(chan struct{}),
	}
	return n
}

func (n *Network) Start() {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return
	}
	n.running = true
	n.mu.Unlock()

	go n.processMessages()
}

func (n *Network) Stop() {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return
	}
	n.running = false
	n.mu.Unlock()

	close(n.stopCh)
}

func (n *Network) processMessages() {
	for {
		select {
		case <-n.stopCh:
			return
		case job := <-n.msgQueue:
			// simulate network delay using sleep
			if n.delay > 0 {
				time.Sleep(n.delay)
			}

			n.mu.RLock()
			peer, exists := n.peers[job.to]
			n.mu.RUnlock()

			if exists && peer.Network != nil {
				peer.Network.deliverMessage(job.msg)
			}
		}
	}
}

func (n *Network) SetDelay(delay time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.delay = delay
}

func (n *Network) AddPeer(id types.NodeID, address string, network *Network) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.peers[id] = &Peer{
		ID:      id,
		Address: address,
		Network: network,
	}
}

func (n *Network) RemovePeer(id types.NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, id)
}

func (n *Network) RegisterHandler(msgType types.MessageType, handler func(msg *types.Message)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers[msgType] = append(n.handlers[msgType], MessageHandler(handler))
}

// Broadcast sends a message to all peers.
func (n *Network) Broadcast(ctx context.Context, msg *types.Message) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	n.mu.RLock()
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.RUnlock()

	msg.From = n.nodeID
	msg.Timestamp = time.Now()

	for _, peer := range peers {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}

		// make a copy for each peer
		msgCopy := *msg
		select {
		case n.msgQueue <- &deliveryJob{to: peer.ID, msg: &msgCopy}:
		default:
			// Queue full, drop message
		}
	}

	return nil
}

// Send sends a message to a specific peer
func (n *Network) Send(to types.NodeID, msg *types.Message) error {
	n.mu.RLock()
	_, exists := n.peers[to]
	n.mu.RUnlock()

	if !exists {
		return errors.New("peer not found")
	}

	msg.From = n.nodeID
	msg.Timestamp = time.Now()

	select {
	case n.msgQueue <- &deliveryJob{to: to, msg: msg}:
		return nil
	default:
		return errors.New("message queue full")
	}
}

// deliverMessage delivers a message to handlers
func (n *Network) deliverMessage(msg *types.Message) {
	n.mu.RLock()
	handlers := n.handlers[msg.Type]
	n.mu.RUnlock()

	for _, handler := range handlers {
		handler(msg)
	}
}

func (n *Network) GetPeers() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := make([]types.NodeID, 0, len(n.peers))
	for id := range n.peers {
		peers = append(peers, id)
	}
	return peers
}

func (n *Network) PeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

func EncodeMessage(msg *types.Message) ([]byte, error) {
	return json.Marshal(msg)
}

func DecodeMessage(data []byte) (*types.Message, error) {
	var msg types.Message
	err := json.Unmarshal(data, &msg)
	return &msg, err
}
