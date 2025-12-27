package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// MessageHandler is called when a message is received.
type MessageHandler func(msg *types.Message)

// InMemoryNetwork implements protocol.NetworkInterface with an in-process message bus.
type InMemoryNetwork struct {
	mu sync.RWMutex

	nodeID   types.NodeID
	peers    map[types.NodeID]*Peer
	handlers map[types.MessageType][]MessageHandler

	delay time.Duration

	msgQueue chan *deliveryJob
	stopCh   chan struct{}
	running  bool
}

var _ protocol.NetworkInterface = (*InMemoryNetwork)(nil)

// Peer represents a connected peer in the network.
type Peer struct {
	ID      types.NodeID
	Address string
	deliver func(*types.Message)
}

// deliveryJob represents a message to be delivered.
type deliveryJob struct {
	peer *Peer
	msg  *types.Message
}

func NewInMemoryNetwork(nodeID types.NodeID) *InMemoryNetwork {
	return &InMemoryNetwork{
		nodeID:   nodeID,
		peers:    make(map[types.NodeID]*Peer),
		handlers: make(map[types.MessageType][]MessageHandler),
		msgQueue: make(chan *deliveryJob, 10000),
		stopCh:   make(chan struct{}),
	}
}

func NewNetwork(nodeID types.NodeID) *InMemoryNetwork {
	return NewInMemoryNetwork(nodeID)
}

func (n *InMemoryNetwork) LocalID() types.NodeID {
	return n.nodeID
}

// Start begins processing incoming messages.
func (n *InMemoryNetwork) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return nil
	}

	if n.msgQueue == nil {
		n.msgQueue = make(chan *deliveryJob, 10000)
	}
	if n.stopCh == nil {
		n.stopCh = make(chan struct{})
	}
	n.running = true
	msgQueue := n.msgQueue
	stopCh := n.stopCh
	n.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	go n.processMessages(ctx, msgQueue, stopCh)
	return nil
}

// Stop stops processing messages.
func (n *InMemoryNetwork) Stop() error {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return nil
	}
	n.running = false
	if n.stopCh != nil {
		close(n.stopCh)
	}
	// allow re-start by reinitializing channels
	n.stopCh = nil
	n.msgQueue = nil
	n.mu.Unlock()
	return nil
}

func (n *InMemoryNetwork) processMessages(ctx context.Context, queue <-chan *deliveryJob, stopCh <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case job, ok := <-queue:
			if !ok {
				return
			}

			if job == nil || job.peer == nil || job.msg == nil {
				continue
			}

			// simulate network delay using sleep
			n.mu.RLock()
			delay := n.delay
			n.mu.RUnlock()
			if delay > 0 {
				time.Sleep(delay)
			}

			if job.peer.deliver != nil {
				job.peer.deliver(job.msg)
			}
		}
	}
}

func (n *InMemoryNetwork) SetDelay(delay time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.delay = delay
}

func (n *InMemoryNetwork) AddPeer(id types.NodeID, address string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[id] = &Peer{
		ID:      id,
		Address: address,
	}
	return nil
}

func (n *InMemoryNetwork) ConnectLocalPeer(id types.NodeID, address string, peer *InMemoryNetwork) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[id] = &Peer{
		ID:      id,
		Address: address,
		deliver: peer.deliverMessage,
	}
}

func (n *InMemoryNetwork) RemovePeer(id types.NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, id)
}

// RegisterHandler registers a callback for a given message type.
func (n *InMemoryNetwork) RegisterHandler(msgType types.MessageType, handler func(msg *types.Message)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers[msgType] = append(n.handlers[msgType], MessageHandler(handler))
}

// Send sends a message to a specific peer.
func (n *InMemoryNetwork) Send(ctx context.Context, to types.NodeID, msg *types.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	n.mu.RLock()
	running := n.running
	peer := n.peers[to]
	queue := n.msgQueue
	n.mu.RUnlock()

	if !running {
		return errors.New("network not running")
	}
	if peer == nil {
		return fmt.Errorf("peer %s not found", to)
	}
	if peer.deliver == nil {
		return fmt.Errorf("peer %s has no delivery path", to)
	}

	msg.From = n.nodeID
	msg.Timestamp = time.Now()

	job := &deliveryJob{peer: peer, msg: msg}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case queue <- job:
		return nil
	default:
		return errors.New("message queue full")
	}
}

// Broadcast sends a message to all peers.
func (n *InMemoryNetwork) Broadcast(ctx context.Context, msg *types.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	n.mu.RLock()
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	queue := n.msgQueue
	running := n.running
	n.mu.RUnlock()

	if !running {
		return errors.New("network not running")
	}

	msg.From = n.nodeID
	msg.Timestamp = time.Now()

	for _, peer := range peers {
		if peer.deliver == nil {
			continue
		}

		msgCopy := *msg
		select {
		case <-ctx.Done():
			return ctx.Err()
		case queue <- &deliveryJob{peer: peer, msg: &msgCopy}:
		default:
			// Queue full, drop message to keep simulation running
		}
	}

	return nil
}

func (n *InMemoryNetwork) Peers() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := make([]types.NodeID, 0, len(n.peers))
	for id := range n.peers {
		peers = append(peers, id)
	}
	return peers
}

func (n *InMemoryNetwork) PeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

// deliverMessage delivers a message to registered handlers.
func (n *InMemoryNetwork) deliverMessage(msg *types.Message) {
	n.mu.RLock()
	handlers := n.handlers[msg.Type]
	n.mu.RUnlock()

	for _, handler := range handlers {
		handler(msg)
	}
}

func EncodeMessage(msg *types.Message) ([]byte, error) {
	wrapper := struct {
		Type      types.MessageType `json:"type"`
		From      types.NodeID      `json:"from"`
		Timestamp time.Time         `json:"timestamp"`
		Payload   interface{}       `json:"payload"`
	}{
		Type:      msg.Type,
		From:      msg.From,
		Timestamp: msg.Timestamp,
	}

	switch msg.Type {
	case types.MsgPropose:
		switch p := msg.Payload.(type) {
		case *types.ProposeMessage:
			wrapper.Payload = p
		case types.ProposeMessage:
			wrapper.Payload = &p
		default:
			return nil, fmt.Errorf("invalid payload for MsgPropose: %T", msg.Payload)
		}
	case types.MsgShare:
		switch p := msg.Payload.(type) {
		case *types.ShareMessage:
			wrapper.Payload = p
		case types.ShareMessage:
			wrapper.Payload = &p
		default:
			return nil, fmt.Errorf("invalid payload for MsgShare: %T", msg.Payload)
		}
	case types.MsgVote:
		switch p := msg.Payload.(type) {
		case *types.VoteMessage:
			wrapper.Payload = p
		case types.VoteMessage:
			wrapper.Payload = &p
		default:
			return nil, fmt.Errorf("invalid payload for MsgVote: %T", msg.Payload)
		}
	case types.MsgConfirm:
		switch p := msg.Payload.(type) {
		case *types.ConfirmMessage:
			wrapper.Payload = p
		case types.ConfirmMessage:
			wrapper.Payload = &p
		default:
			return nil, fmt.Errorf("invalid payload for MsgConfirm: %T", msg.Payload)
		}
	case types.MsgAwake:
		switch p := msg.Payload.(type) {
		case *types.AwakeMessage:
			wrapper.Payload = p
		case types.AwakeMessage:
			wrapper.Payload = &p
		default:
			return nil, fmt.Errorf("invalid payload for MsgAwake: %T", msg.Payload)
		}
	default:
		return nil, fmt.Errorf("unknown message type %d", msg.Type)
	}

	return json.Marshal(wrapper)
}

func DecodeMessage(data []byte) (*types.Message, error) {
	var header struct {
		Type      types.MessageType `json:"type"`
		From      types.NodeID      `json:"from"`
		Timestamp time.Time         `json:"timestamp"`
		Payload   json.RawMessage   `json:"payload"`
	}

	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}

	msg := &types.Message{
		Type:      header.Type,
		From:      header.From,
		Timestamp: header.Timestamp,
	}

	switch header.Type {
	case types.MsgPropose:
		var p types.ProposeMessage
		if err := json.Unmarshal(header.Payload, &p); err != nil {
			return nil, err
		}
		msg.Payload = &p
	case types.MsgShare:
		var p types.ShareMessage
		if err := json.Unmarshal(header.Payload, &p); err != nil {
			return nil, err
		}
		msg.Payload = &p
	case types.MsgVote:
		var p types.VoteMessage
		if err := json.Unmarshal(header.Payload, &p); err != nil {
			return nil, err
		}
		msg.Payload = &p
	case types.MsgConfirm:
		var p types.ConfirmMessage
		if err := json.Unmarshal(header.Payload, &p); err != nil {
			return nil, err
		}
		msg.Payload = &p
	case types.MsgAwake:
		var p types.AwakeMessage
		if err := json.Unmarshal(header.Payload, &p); err != nil {
			return nil, err
		}
		msg.Payload = &p
	default:
		return nil, fmt.Errorf("unknown message type %d", header.Type)
	}

	return msg, nil
}
