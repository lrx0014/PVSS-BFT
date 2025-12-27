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

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/network"
	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

// SimulatedNetwork creates a example network for demo purpose
type SimulatedNetwork struct {
	mu         sync.RWMutex
	transports map[types.NodeID]*network.InMemoryNetwork
	delay      time.Duration
}

func NewSimulatedNetwork(delay time.Duration) *SimulatedNetwork {
	return &SimulatedNetwork{
		transports: make(map[types.NodeID]*network.InMemoryNetwork),
		delay:      delay,
	}
}

func (sn *SimulatedNetwork) AddNode(nodeID types.NodeID) *network.InMemoryNetwork {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	net := network.NewInMemoryNetwork(nodeID)
	net.SetDelay(sn.delay)

	// Connect to all existing nodes
	for id, existingNet := range sn.transports {
		net.ConnectLocalPeer(id, "", existingNet)
		existingNet.ConnectLocalPeer(nodeID, "", net)
	}

	sn.transports[nodeID] = net
	return net
}

func (sn *SimulatedNetwork) RemoveNode(nodeID types.NodeID) {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	// remove from all network peers
	for id, net := range sn.transports {
		if id != nodeID {
			net.RemovePeer(nodeID)
		}
	}

	delete(sn.transports, nodeID)
}

func (sn *SimulatedNetwork) Start(ctx context.Context) {
	sn.mu.RLock()
	defer sn.mu.RUnlock()

	for _, net := range sn.transports {
		net.Start(ctx)
	}
}

func (sn *SimulatedNetwork) Stop() {
	sn.mu.RLock()
	defer sn.mu.RUnlock()

	for _, net := range sn.transports {
		net.Stop()
	}
}

func main() {
	logger := log.New(log.NewTextHandler(os.Stdout, &log.HandlerOptions{
		Level: log.LevelInfo,
	}))
	log.SetDefault(logger)

	log.Info("=== PVSS-BFT Sleepy Demo: Node Sleep/Wake Simulation ===")

	// Configuration
	numNodes := 4
	delta := 500 * time.Millisecond

	log.Info("Configuration",
		"num_nodes", numNodes,
		"delta", delta,
		"view_duration", 4*delta)

	simNet := NewSimulatedNetwork(10 * time.Millisecond)

	// Shared PVSS parameters for all nodes to ensure compatible shares
	basePVSS, err := crypto.NewPVSS()
	if err != nil {
		log.Error("Failed to create shared PVSS parameters", "error", err)
		return
	}

	nodes := make([]*protocol.Node, numNodes)
	for i := 0; i < numNodes; i++ {
		nodeID := types.NodeID(fmt.Sprintf("node-%d", i))

		net := simNet.AddNode(nodeID)

		config := &protocol.Config{
			NodeID:       nodeID,
			Delta:        delta,
			ViewDuration: 4 * delta,
			PVSSParams:   basePVSS,
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
			log.Info("Block decided",
				"node_id", nodeID,
				"view", block.View,
				"height", block.Height,
				"proposer", block.Proposer,
				"tx_count", len(block.Transactions))
		})
	}

	// register all nodes as participants with each other
	for _, node := range nodes {
		info := node.GetPublicInfo()
		for _, otherNode := range nodes {
			otherNode.AddParticipant(info)
		}
	}

	// Create main context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	simNet.Start(ctx)

	log.Info("Starting all nodes")
	for i, node := range nodes {
		if err := node.Start(ctx); err != nil {
			log.Error("Failed to start node", "error", err)
			return
		}
		log.Info("Node started", "node_id", fmt.Sprintf("node-%d", i))
	}

	// Simulate node-1 going to sleep and waking up
	go func() {
		sleepNode := nodes[1]
		sleepNodeID := types.NodeID("node-1")

		// Let consensus run for a while with all nodes
		log.Info("Waiting for initial consensus rounds...")
		time.Sleep(3 * time.Second)

		log.Warn(">>> SIMULATION: node-1 going to SLEEP <<<")
		sleepNode.Sleep()
		log.Info("Node sleeping",
			"node_id", sleepNodeID,
			"state", "sleepy",
			"current_view", sleepNode.GetCurrentView())

		// Sleep for several views (10 seconds = 5 views at 2s per view)
		time.Sleep(10 * time.Second)

		log.Warn(">>> SIMULATION: node-1 WAKING UP <<<")
		sleepNode.Wake()
		log.Info("Node awake",
			"node_id", sleepNodeID,
			"state", "awake",
			"current_view", sleepNode.GetCurrentView())
	}()

	// simulate continuous transactions
	go func() {
		txCounter := 0
		ticker := time.NewTicker(delta)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tx := types.Transaction{
					ID:        fmt.Sprintf("tx-%d", txCounter),
					Data:      []byte(fmt.Sprintf("Transaction data %d", txCounter)),
					Timestamp: time.Now(),
					Sender:    "client",
				}

				// Send to node-0 (always awake)
				if err := nodes[0].AddTransaction(ctx, tx); err != nil {
					log.Warn("Failed to add transaction", "error", err)
					return
				}
				txCounter++
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
		log.Info("=== Demo complete ===")
		cancel()
	}

	for _, node := range nodes {
		node.Stop()
	}
	simNet.Stop()

	// Print final state
	log.Info("")
	log.Info("=== Final Chain State ===")
	for i, node := range nodes {
		chain := node.GetChain()
		nodeID := fmt.Sprintf("node-%d", i)
		state := "awake"
		if node.GetState() == types.StateSleepy {
			state = "sleepy"
		}
		log.Info("Chain state",
			"node_id", nodeID,
			"height", chain.Height(),
			"state", state,
			"running", node.IsRunning())
	}
}
