package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "log/slog"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/network"
	"github.com/lrx0014/pvss-bft/pkg/protocol"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

var tcpDemoConfig = []struct {
	id      types.NodeID
	address string
}{
	{types.NodeID("node-0"), "127.0.0.1:9201"},
	{types.NodeID("node-1"), "127.0.0.1:9202"},
	{types.NodeID("node-2"), "127.0.0.1:9203"},
	{types.NodeID("node-3"), "127.0.0.1:9204"},
}

func main() {
	logger := log.New(log.NewTextHandler(os.Stdout, &log.HandlerOptions{
		Level: log.LevelInfo,
	}))
	log.SetDefault(logger)

	log.Info("PVSS-BFT Demo: Starting TCP Network")

	// configuration
	delta := 1000 * time.Millisecond
	viewDuration := 4 * delta

	// Shared PVSS parameters for all nodes to ensure compatible shares
	basePVSS, err := crypto.NewPVSS()
	if err != nil {
		log.Error("Failed to create shared PVSS parameters", "error", err)
		return
	}

	pvss, _ := json.Marshal(*basePVSS)
	log.Info(fmt.Sprintf("pvss_params: %s", string(pvss)))

	transports := make(map[types.NodeID]*network.TCPNetwork)
	for _, cfg := range tcpDemoConfig {
		transports[cfg.id] = network.NewTCPNetwork(cfg.id, cfg.address)
	}

	for _, cfg := range tcpDemoConfig {
		net := transports[cfg.id]
		for _, peer := range tcpDemoConfig {
			if peer.id == cfg.id {
				continue
			}
			if err := net.AddPeer(peer.id, peer.address); err != nil {
				log.Error("Failed to add peer", "node_id", cfg.id, "peer", peer.id, "error", err)
				return
			}
		}
	}

	nodes := make([]*protocol.Node, 0, len(tcpDemoConfig))
	for _, cfg := range tcpDemoConfig {
		config := &protocol.Config{
			NodeID:       cfg.id,
			Delta:        delta,
			ViewDuration: viewDuration,
			PVSSParams:   basePVSS,
		}

		node, err := protocol.NewNode(config, transports[cfg.id])
		if err != nil {
			log.Error("Failed to create node", "node_id", cfg.id, "error", err)
			return
		}

		node.SetOnBlockDecided(func(block *types.Block) {
			log.Info("Decided block",
				"node_id", cfg.id,
				"view", block.View,
				"height", block.Height,
				"proposer", block.Proposer)
		})

		nodes = append(nodes, node)
	}

	// Register participants across nodes so public keys are known.
	for _, node := range nodes {
		info := node.GetPublicInfo()
		for _, otherNode := range nodes {
			otherNode.AddParticipant(info)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start nodes.
	for _, net := range transports {
		if err := net.Start(ctx); err != nil {
			log.Error("Failed to start transport", "error", err)
			return
		}
	}

	log.Info("Starting consensus protocol over TCP")
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
		log.Info("Shutting down TCP demo...")
		cancel()
	case <-time.After(30 * time.Second):
		log.Info("TCP demo complete")
		cancel()
	}

	for _, node := range nodes {
		node.Stop()
	}
}
