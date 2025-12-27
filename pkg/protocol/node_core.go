package protocol

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	log "log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

const (
	DefaultViewMultiplier          = 4 // (4Δ)
	DefaultMaxTransactionsPerBlock = 100
)

// Config configuration for the PVSS-BFT node
type Config struct {
	NodeID       types.NodeID
	Delta        time.Duration // Network delay bound Δ
	ViewDuration time.Duration // Total view duration (4Δ)
	PVSSParams   *crypto.PVSS  // Shared PVSS parameters (p, q, g, h)
}

func DefaultConfig(nodeID types.NodeID) *Config {
	delta := time.Second
	return &Config{
		NodeID:       nodeID,
		Delta:        delta,
		ViewDuration: DefaultViewMultiplier * delta,
	}
}

type Node struct {
	mu sync.RWMutex

	config *Config

	// Cryptographic components
	signer   *crypto.Signer
	vrf      *crypto.VRF
	vrfKey   *crypto.VRFKeyPair
	pvss     *crypto.PVSS
	pvssPriv *big.Int // private key
	pvssPub  *big.Int // public key

	// Network component
	network NetworkInterface

	// State of the node
	state       types.NodeState
	currentView types.View
	consensus   *types.ConsensusState
	chain       *types.Chain

	participants map[types.NodeID]*Participant

	// Transaction pool
	txPool []types.Transaction

	// Channels for timers and stopping management
	viewTimer  *time.Timer
	phaseTimer *time.Timer
	stopCh     chan struct{}

	// Running state
	running bool

	// Callbacks
	onBlockDecided func(*types.Block)

	// Logger
	logger *log.Logger

	// Context for cancellation and context management
	ctx    context.Context
	cancel context.CancelFunc
}

// Participant contains information about a network participant
type Participant struct {
	ID         types.NodeID
	PublicKey  *ecdsa.PublicKey
	PVSSPubKey *big.Int
	VRFPubKey  *ecdsa.PublicKey
	IsActive   bool
}

func NewNode(config *Config, net NetworkInterface) (*Node, error) {
	// cryptographic components
	signer, err := crypto.NewSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	vrf := crypto.NewVRF()
	vrfKey, err := vrf.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate VRF key: %w", err)
	}

	var pvss *crypto.PVSS
	if config.PVSSParams != nil {
		// use shared parameters for compatibility across nodes
		pvss = crypto.NewPVSSWithParams(config.PVSSParams.P, config.PVSSParams.Q, config.PVSSParams.G, config.PVSSParams.H)
	} else {
		pvss, err = crypto.NewPVSS()
		if err != nil {
			return nil, fmt.Errorf("failed to create PVSS: %w", err)
		}
	}

	pvssPriv, pvssPub, err := pvss.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PVSS keys: %w", err)
	}

	logger := log.Default()

	node := &Node{
		config:       config,
		signer:       signer,
		vrf:          vrf,
		vrfKey:       vrfKey,
		pvss:         pvss,
		pvssPriv:     pvssPriv,
		pvssPub:      pvssPub,
		network:      net,
		state:        types.StateAwake,
		currentView:  0,
		chain:        types.NewChain(),
		participants: make(map[types.NodeID]*Participant),
		txPool:       make([]types.Transaction, 0),
		stopCh:       make(chan struct{}),
		logger:       logger,
	}

	// Register self as a participant
	node.participants[config.NodeID] = &Participant{
		ID:         config.NodeID,
		PublicKey:  signer.PublicKey(),
		PVSSPubKey: pvssPub,
		VRFPubKey:  vrfKey.PublicKey,
		IsActive:   true,
	}

	// Register message handlers
	node.registerHandlers()

	return node, nil
}

func (n *Node) registerHandlers() {
	n.network.RegisterHandler(types.MsgPropose, func(msg *types.Message) { n.handlePropose(msg) })
	n.network.RegisterHandler(types.MsgShare, func(msg *types.Message) { n.handleShare(msg) })
	n.network.RegisterHandler(types.MsgVote, func(msg *types.Message) { n.handleVote(msg) })
	n.network.RegisterHandler(types.MsgConfirm, func(msg *types.Message) { n.handleConfirm(msg) })
	n.network.RegisterHandler(types.MsgAwake, func(msg *types.Message) { n.handleAwake(msg) })
	n.network.RegisterHandler(types.MsgSyncRequest, func(msg *types.Message) { n.handleSyncRequest(msg) })
	n.network.RegisterHandler(types.MsgSyncResponse, func(msg *types.Message) { n.handleSyncResponse(msg) })
}

func (n *Node) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return nil
	}

	n.ctx, n.cancel = context.WithCancel(ctx)
	n.running = true
	n.mu.Unlock()

	if err := n.network.Start(n.ctx); err != nil {
		n.mu.Lock()
		n.running = false
		n.mu.Unlock()
		return err
	}

	n.startView(0)

	return nil
}

func (n *Node) Stop() {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return
	}
	n.running = false

	if n.cancel != nil {
		n.cancel()
	}

	close(n.stopCh)

	if n.viewTimer != nil {
		n.viewTimer.Stop()
	}
	if n.phaseTimer != nil {
		n.phaseTimer.Stop()
	}
	n.mu.Unlock()

	_ = n.network.Stop()
}

func (n *Node) AddParticipant(p *Participant) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.participants[p.ID] = p
}

func (n *Node) AddTransaction(ctx context.Context, tx types.Transaction) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.txPool = append(n.txPool, tx)
	return nil
}

func (n *Node) SetOnBlockDecided(callback func(*types.Block)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onBlockDecided = callback
}

func (n *Node) SetLogger(logger *log.Logger) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logger = logger
}

// Sleep puts the node into sleep mode, stops participating in consensus
func (n *Node) Sleep() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.state = types.StateSleepy
}

// Wake wakes the node from sleep mode
func (n *Node) Wake() {
	n.mu.Lock()
	n.state = types.StateAwake
	n.mu.Unlock()

	// After waking, synchronize with peers to catch up on missed blocks
	go n.synchronizeWithPeers()
}

func (n *Node) GetState() types.NodeState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.state
}

func (n *Node) GetPublicInfo() *Participant {
	return &Participant{
		ID:         n.config.NodeID,
		PublicKey:  n.signer.PublicKey(),
		PVSSPubKey: n.pvssPub,
		VRFPubKey:  n.vrfKey.PublicKey,
		IsActive:   n.state == types.StateAwake,
	}
}

func (n *Node) GetChain() *types.Chain {
	return n.chain
}

func (n *Node) GetCurrentView() types.View {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.currentView
}

func (n *Node) IsRunning() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.running
}
