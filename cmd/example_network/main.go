// Package main provides a complete example of using PVSS-BFT with a simulated network.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "log/slog"

	"github.com/lrx0014/pvss-bft/pkg/network"
	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// SimulatedNetwork creates a example network for demo purpose
type SimulatedNetwork struct {
	mu       sync.RWMutex
	networks map[types.NodeID]*network.Network
	delay    time.Duration
}

func NewSimulatedNetwork(delay time.Duration) *SimulatedNetwork {
	return &SimulatedNetwork{
		networks: make(map[types.NodeID]*network.Network),
		delay:    delay,
	}
}

func (sn *SimulatedNetwork) AddNode(nodeID types.NodeID) *network.Network {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	net := network.NewNetwork(nodeID)
	net.SetDelay(sn.delay)

	// Connect to all existing nodes
	for id, existingNet := range sn.networks {
		net.AddPeer(id, "", existingNet)
		existingNet.AddPeer(nodeID, "", net)
	}

	sn.networks[nodeID] = net
	return net
}

func (sn *SimulatedNetwork) RemoveNode(nodeID types.NodeID) {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	// remove from all network peers
	for id, net := range sn.networks {
		if id != nodeID {
			net.RemovePeer(nodeID)
		}
	}

	delete(sn.networks, nodeID)
}

func (sn *SimulatedNetwork) Start() {
	sn.mu.RLock()
	defer sn.mu.RUnlock()

	for _, net := range sn.networks {
		net.Start()
	}
}

func (sn *SimulatedNetwork) Stop() {
	sn.mu.RLock()
	defer sn.mu.RUnlock()

	for _, net := range sn.networks {
		net.Stop()
	}
}

func main() {
	logger := log.New(log.NewTextHandler(os.Stdout, &log.HandlerOptions{
		Level: log.LevelInfo,
	}))
	log.SetDefault(logger)

	log.Info("PVSS-BFT Demo: Starting Simulated Network")

	// Configuration
	numNodes := 4
	delta := 500 * time.Millisecond

	log.Info("Starting nodes",
		"num_nodes", numNodes,
		"delta", delta)

	simNet := NewSimulatedNetwork(10 * time.Millisecond)

	nodes := make([]*protocol.Node, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeID := types.NodeID(fmt.Sprintf("node-%d", i))

		net := simNet.AddNode(nodeID)

		config := &protocol.Config{
			NodeID:       nodeID,
			Delta:        delta,
			ViewDuration: 4 * delta,
		}

		node, err := protocol.NewNode(config, net)
		if err != nil {
			log.Error("Failed to create node",
				"node_id", nodeID,
				"error", err)
			return
		}

		nodes[i] = node

		// callback for decided blocks
		node.SetOnBlockDecided(func(block *types.Block) {
			log.Info("Decided block",
				"node_id", nodeID,
				"view", block.View,
				"height", block.Height,
				"proposer", block.Proposer)
		})
	}

	// register all nodes as participants with each other
	for _, node := range nodes {
		info := node.GetPublicInfo()
		for _, otherNode := range nodes {
			otherNode.AddParticipant(info)
		}
	}

	simNet.Start()

	// Create main context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Starting consensus protocol")
	for _, node := range nodes {
		if err := node.Start(ctx); err != nil {
			log.Error("Failed to start node", "error", err)
			return
		}
	}

	// simulate some transactions
	go func() {
		for i := 0; i < 10; i++ {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delta):
				tx := types.Transaction{
					ID:        fmt.Sprintf("tx-%d", i),
					Data:      []byte(fmt.Sprintf("Transaction data %d", i)),
					Timestamp: time.Now(),
					Sender:    "client",
				}

				if err := nodes[0].AddTransaction(ctx, tx); err != nil {
					log.Warn("Failed to add transaction", "error", err)
					return
				}
			}
		}
	}()

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Info("Shutting down...")
		cancel()
	case <-time.After(30 * time.Second):
		log.Info("Demo complete")
		cancel()
	}

	for _, node := range nodes {
		node.Stop()
	}
	simNet.Stop()

	log.Info("Final chain state")
	for _, node := range nodes {
		chain := node.GetChain()
		log.Info("Chain state",
			"node_id", node.GetPublicInfo().ID,
			"height", chain.Height())
	}
}
