package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// TCPNetwork implements NetworkInterface over TCP sockets.
type TCPNetwork struct {
	mu sync.RWMutex

	nodeID   types.NodeID
	address  string
	peers    map[types.NodeID]string // id -> address
	handlers map[types.MessageType][]MessageHandler

	listener net.Listener
	running  bool
	wg       sync.WaitGroup
}

var _ protocol.NetworkInterface = (*TCPNetwork)(nil)

func NewTCPNetwork(nodeID types.NodeID, address string) *TCPNetwork {
	return &TCPNetwork{
		nodeID:   nodeID,
		address:  address,
		peers:    make(map[types.NodeID]string),
		handlers: make(map[types.MessageType][]MessageHandler),
	}
}

func (n *TCPNetwork) LocalID() types.NodeID {
	return n.nodeID
}

func (n *TCPNetwork) RegisterHandler(msgType types.MessageType, handler func(msg *types.Message)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers[msgType] = append(n.handlers[msgType], MessageHandler(handler))
}

func (n *TCPNetwork) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return nil
	}

	ln, err := net.Listen("tcp", n.address)
	if err != nil {
		n.mu.Unlock()
		return err
	}

	n.listener = ln
	n.running = true
	n.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	n.wg.Add(1)
	go n.acceptLoop(ctx, ln)
	return nil
}

func (n *TCPNetwork) Stop() error {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return nil
	}

	n.running = false
	if n.listener != nil {
		_ = n.listener.Close()
	}
	n.mu.Unlock()

	n.wg.Wait()
	return nil
}

func (n *TCPNetwork) acceptLoop(ctx context.Context, ln net.Listener) {
	defer n.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}

		n.wg.Add(1)
		go n.handleConn(ctx, conn)
	}
}

func (n *TCPNetwork) handleConn(ctx context.Context, conn net.Conn) {
	defer n.wg.Done()
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	reader := bufio.NewReader(conn)
	for {
		if ctx.Err() != nil {
			break
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		if len(line) == 0 {
			continue
		}

		msg, err := DecodeMessage(line)
		if err != nil {
			continue
		}
		n.deliverMessage(msg)
	}

	close(done)
}

func (n *TCPNetwork) AddPeer(id types.NodeID, address string) error {
	if address == "" {
		return errors.New("address is required for TCP peer")
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[id] = address
	return nil
}

func (n *TCPNetwork) RemovePeer(id types.NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, id)
}

func (n *TCPNetwork) Send(ctx context.Context, to types.NodeID, msg *types.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}

	n.mu.RLock()
	addr, ok := n.peers[to]
	running := n.running
	n.mu.RUnlock()

	if !running {
		return errors.New("network not running")
	}
	if !ok {
		return fmt.Errorf("peer %s not found", to)
	}

	msg.From = n.nodeID
	msg.Timestamp = time.Now()

	data, err := EncodeMessage(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

func (n *TCPNetwork) Broadcast(ctx context.Context, msg *types.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}

	n.mu.RLock()
	peerAddrs := make(map[types.NodeID]string, len(n.peers))
	for id, addr := range n.peers {
		peerAddrs[id] = addr
	}
	running := n.running
	n.mu.RUnlock()

	if !running {
		return errors.New("network not running")
	}

	var firstErr error
	for id := range peerAddrs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msgCopy := *msg
		if err := n.Send(ctx, id, &msgCopy); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (n *TCPNetwork) Peers() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()
	peers := make([]types.NodeID, 0, len(n.peers))
	for id := range n.peers {
		peers = append(peers, id)
	}
	return peers
}

func (n *TCPNetwork) deliverMessage(msg *types.Message) {
	n.mu.RLock()
	handlers := n.handlers[msg.Type]
	n.mu.RUnlock()

	for _, handler := range handlers {
		handler(msg)
	}
}
