package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	log "log/slog"
	"math/big"
	"reflect"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
	"github.com/lrx0014/pvss-bft/pkg/types"
)

const (
	DefaultViewMultiplier          = 4 // (4Δ)
	DefaultMaxTransactionsPerBlock = 100
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

func (n *Node) GetPublicInfo() *Participant {
	return &Participant{
		ID:         n.config.NodeID,
		PublicKey:  n.signer.PublicKey(),
		PVSSPubKey: n.pvssPub,
		VRFPubKey:  n.vrfKey.PublicKey,
		IsActive:   n.state == types.StateAwake,
	}
}

// startView initializes a new view
func (n *Node) startView(view types.View) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.currentView = view
	n.consensus = types.NewConsensusState(view)

	// Set active nodes based on previous round commits
	for id, p := range n.participants {
		if p.IsActive {
			n.consensus.ActiveNodes[id] = true
		}
	}

	// Start Phase 1 timer
	n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
		n.advancePhase(types.PhaseShare)
	})

	// Execute Phase 1
	go n.executePhase1()
}

// advancePhase moves to the next phase
func (n *Node) advancePhase(phase types.Phase) {
	n.mu.Lock()
	if n.consensus == nil {
		n.mu.Unlock()
		return
	}
	n.consensus.Phase = phase
	n.mu.Unlock()

	switch phase {
	case types.PhaseShare:
		// Phase 2 timer
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.advancePhase(types.PhaseVote)
		})
		go n.executePhase2()

	case types.PhaseVote:
		// Phase 3 timer
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.advancePhase(types.PhaseConfirm)
		})
		go n.executePhase3()

	case types.PhaseConfirm:
		// Phase 4 timer (also view timer)
		n.phaseTimer = time.AfterFunc(n.config.Delta, func() {
			n.finalizeView()
		})
		go n.executePhase4()
	}
}

// finalizeView completes the current view and starts the next
func (n *Node) finalizeView() {
	n.mu.Lock()
	currentView := n.currentView
	decidedBlock := n.consensus.DecidedBlock
	n.mu.Unlock()

	if decidedBlock != nil {
		n.chain.Append(decidedBlock)

		n.mu.RLock()
		callback := n.onBlockDecided
		n.mu.RUnlock()

		if callback != nil {
			callback(decidedBlock)
		}
	}

	// next view
	n.startView(currentView + 1)
}

// executePhase1 executes Phase 1: Block Proposal and Share Distribution
func (n *Node) executePhase1() {
	n.mu.RLock()
	if n.state != types.StateAwake {
		n.mu.RUnlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// create a block
	block := n.createBlock(view)

	// pre-commit signal
	preCommit := types.PreCommit{
		NodeID:       nodeID,
		View:         view,
		NextViewJoin: true, // We intend to join next round
	}

	// compute hash of block || precommit
	blockData, _ := json.Marshal(block)
	preCommitData, _ := json.Marshal(preCommit)
	combinedHash := crypto.HashMultiple(blockData, preCommitData)

	// create PVSS shares
	pvssBundle, err := n.createPVSSBundle(combinedHash)
	if err != nil {
		n.logError("Failed to create PVSS bundle", "error", err)
		return
	}

	// generate VRF output
	vrfInput := []byte(fmt.Sprintf("view:%d", view))
	vrfProof, err := n.vrf.Evaluate(n.vrfKey.PrivateKey, vrfInput)
	if err != nil {
		n.logError("Failed to generate VRF", "error", err)
		return
	}

	// create propose message
	proposeMsg := &types.ProposeMessage{
		View:  view,
		Block: *block,
		PVSS:  *pvssBundle,
		VRF: types.VRFOutput{
			Value: vrfProof.Output,
			Proof: vrfProof.Proof,
		},
		PreCommit: preCommit,
	}

	// sign and broadcast
	msgData, _ := json.Marshal(proposeMsg)
	sig, _ := n.signer.Sign(msgData)
	proposeMsg.Signature = sig

	n.logInfo("Phase1: propose", "vrf", formatVRF(vrfProof.Output))

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()
	n.broadcast(broadcastCtx, types.MsgPropose, proposeMsg)

	// store our own proposal
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Proposals[nodeID] = proposeMsg
	}
	n.mu.Unlock()
}

// executePhase2 executes Phase 2: Share Verification and Leader Election
func (n *Node) executePhase2() {
	n.mu.RLock()
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Elect leader from valid proposals
	leaderID, maxVRF := n.electLeader(view)
	if leaderID == "" {
		n.logWarn("No valid leader found")
		return
	}

	n.logInfo("Phase2: leader elected", "leader", leaderID, "vrf", formatVRF(maxVRF))

	// Verify and decrypt share from the leader
	decryptedShare, ourShare := n.verifyAndDecryptLeaderShare(leaderID, view, nodeID)
	if decryptedShare == nil {
		return
	}

	// Broadcast decrypted share
	n.broadcastShareMessage(view, leaderID, ourShare, decryptedShare, nodeID)
}

// executePhase3 executes Phase 3: Secret Reconstruction and Voting
func (n *Node) executePhase3() {
	n.mu.RLock()
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Collect and verify shares from other nodes
	shares := n.collectValidShares(view, nodeID)

	// Determine vote based on secret reconstruction
	vote, blockHash := n.determineVote(shares, view, nodeID)

	// Broadcast vote message
	n.broadcastVoteMessage(view, blockHash, vote, nodeID)
}

// executePhase4 executes Phase 4: Confirmation and Consensus
func (n *Node) executePhase4() {
	n.mu.RLock()
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if !n.checkContext(ctx) {
		return
	}

	// Count votes and determine if we should send confirmation
	voteCount, decidedHash := n.countVotes()
	if voteCount == 0 || decidedHash == nil {
		return
	}

	// Broadcast confirmation if we have quorum of votes
	n.broadcastConfirmIfQuorum(view, decidedHash, voteCount, nodeID)

	// Check if we can decide on the block
	consensus := n.requireConsensus(view)
	if consensus != nil {
		n.mu.Lock()
		n.tryDecideBlock(consensus, decidedHash)
		n.mu.Unlock()
	}
}

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

// Helper methods

// formatVRF formats VRF output in scientific notation for readability
func formatVRF(vrfOutput []byte) string {
	vrfInt := new(big.Int).SetBytes(vrfOutput)
	// Convert to float64 for scientific notation
	vrfFloat := new(big.Float).SetInt(vrfInt)
	f64, _ := vrfFloat.Float64()
	return fmt.Sprintf("%.3e", f64)
}

// logWithContext logs with common node context fields
func (n *Node) logInfo(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Info(msg, allArgs...)
}

func (n *Node) logWarn(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Warn(msg, allArgs...)
}

func (n *Node) logError(msg string, args ...interface{}) {
	allArgs := []interface{}{"node", n.config.NodeID, "view", n.currentView}
	allArgs = append(allArgs, args...)
	n.logger.Error(msg, allArgs...)
}

// checkContext returns false if the context is cancelled, true otherwise
func (n *Node) checkContext(ctx context.Context) bool {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return false
		default:
		}
	}
	return true
}

// requireConsensus returns the consensus state if it exists and matches the view, nil otherwise
func (n *Node) requireConsensus(view types.View) *types.ConsensusState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.consensus == nil || n.consensus.View != view {
		return nil
	}
	return n.consensus
}

func (n *Node) unmarshalMessage(msg *types.Message, target interface{}) interface{} {
	// try direct type assertion first
	targetType := reflect.TypeOf(target).Elem()
	if reflect.TypeOf(msg.Payload) == reflect.PtrTo(targetType) {
		return msg.Payload
	}

	// fallback to JSON unmarshaling
	data, err := json.Marshal(msg.Payload)
	if err != nil {
		return nil
	}

	targetValue := reflect.New(targetType)
	if err := json.Unmarshal(data, targetValue.Interface()); err != nil {
		return nil
	}

	return targetValue.Interface()
}

func (n *Node) verifyMessageSignature(msg interface{}, publicKey *ecdsa.PublicKey) bool {
	switch m := msg.(type) {
	case *types.ProposeMessage:
		return verifySignatureForMessage(m, publicKey, func(p *types.ProposeMessage) []byte {
			sig := p.Signature
			p.Signature = nil
			return sig
		})
	case *types.ShareMessage:
		return verifySignatureForMessage(m, publicKey, func(s *types.ShareMessage) []byte {
			sig := s.Signature
			s.Signature = nil
			return sig
		})
	case *types.VoteMessage:
		return verifySignatureForMessage(m, publicKey, func(v *types.VoteMessage) []byte {
			sig := v.Signature
			v.Signature = nil
			return sig
		})
	case *types.ConfirmMessage:
		return verifySignatureForMessage(m, publicKey, func(c *types.ConfirmMessage) []byte {
			sig := c.Signature
			c.Signature = nil
			return sig
		})
	case *types.AwakeMessage:
		return verifySignatureForMessage(m, publicKey, func(a *types.AwakeMessage) []byte {
			sig := a.Signature
			a.Signature = nil
			return sig
		})
	}
	return false
}

func (n *Node) verifyVRF(view types.View, vrf types.VRFOutput, publicKey *ecdsa.PublicKey) bool {
	vrfInput := []byte(fmt.Sprintf("view:%d", view))
	vrfProof := &crypto.VRFProof{
		Output: vrf.Value,
		Proof:  vrf.Proof,
	}
	valid, _ := n.vrf.Verify(publicKey, vrfInput, vrfProof)
	return valid
}

// tryDecideBlock attempts to decide on a block if quorum is reached
func (n *Node) tryDecideBlock(consensus *types.ConsensusState, decidedHash []byte) {
	if consensus.DecidedBlock != nil {
		return
	}

	confirmCount := 0
	for _, cm := range consensus.Confirms {
		if bytes.Equal(cm.BlockHash, decidedHash) {
			confirmCount++
		}
	}

	activeCount := len(consensus.ActiveNodes)
	quorum := activeCount / 2

	if confirmCount >= quorum {
		leaderProposal := consensus.Proposals[consensus.LeaderID]
		if leaderProposal != nil {
			block := leaderProposal.Block
			block.Hash = decidedHash
			consensus.DecidedBlock = &block
		}
	}
}

// electLeader validates proposals and elects the leader based on highest VRF
func (n *Node) electLeader(view types.View) (types.NodeID, []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil {
		return "", nil
	}

	var leaderID types.NodeID
	var maxVRF []byte

	for id, proposal := range n.consensus.Proposals {
		participant := n.participants[id]
		if participant == nil {
			continue
		}

		// Verify VRF
		if !n.verifyVRF(proposal.View, proposal.VRF, participant.VRFPubKey) {
			continue
		}

		// Verify PVSS shares exist
		if len(proposal.PVSS.Shares) == 0 {
			continue
		}

		// Track highest VRF for leader election
		if maxVRF == nil || crypto.CompareVRFOutputs(proposal.VRF.Value, maxVRF) > 0 {
			maxVRF = proposal.VRF.Value
			leaderID = id
		}

		// Track pre-commits for next round
		if proposal.PreCommit.NextViewJoin {
			n.consensus.NextRoundCommits[id] = true
		}
	}

	n.consensus.LeaderID = leaderID
	n.consensus.LeaderVRF = maxVRF

	return leaderID, maxVRF
}

// verifyAndDecryptLeaderShare verifies and decrypts our share from the leader
func (n *Node) verifyAndDecryptLeaderShare(leaderID types.NodeID, view types.View, nodeID types.NodeID) (*big.Int, types.PVSSShare) {
	n.mu.RLock()
	leaderProposal := n.consensus.Proposals[leaderID]
	n.mu.RUnlock()

	if leaderProposal == nil {
		return nil, types.PVSSShare{}
	}

	// Find our share from leader
	var ourShare types.PVSSShare
	for _, share := range leaderProposal.PVSS.Shares {
		if share.Recipient == nodeID {
			ourShare = share
			break
		}
	}

	// Get our participant info
	participant := n.participants[nodeID]
	if participant == nil {
		n.logWarn("Missing participant info for share verification")
		return nil, types.PVSSShare{}
	}

	// Verify encrypted share against leader's commitment
	if !n.pvss.Verify(ourShare.Index, participant.PVSSPubKey, ourShare.Value, leaderProposal.PVSS.Commitment.Coefficients) {
		n.logWarn("Share verification failed")
		return nil, types.PVSSShare{}
	}

	// Decrypt the share for others to reconstruct
	decrypted := n.pvss.DecryptShare(ourShare.Value, n.pvssPriv)
	if decrypted == nil {
		n.logWarn("Failed to decrypt share")
		return nil, types.PVSSShare{}
	}

	return decrypted, ourShare
}

// broadcastShareMessage creates and broadcasts a share message
func (n *Node) broadcastShareMessage(view types.View, leaderID types.NodeID, ourShare types.PVSSShare, decrypted *big.Int, nodeID types.NodeID) {
	shareMsg := &types.ShareMessage{
		View:            view,
		LeaderID:        leaderID,
		LeaderShare:     ourShare,
		DecryptedShare:  decrypted,
		AwakeList:       n.getAwakeList(),
		NextRoundCommit: n.getNextRoundCommits(),
	}

	msgData, _ := json.Marshal(shareMsg)
	sig, _ := n.signer.Sign(msgData)
	shareMsg.Signature = sig

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgShare, shareMsg)

	// Store share message
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.ShareMessages[nodeID] = shareMsg
	}
	n.mu.Unlock()
}

// collectValidShares collects and validates shares from other nodes
func (n *Node) collectValidShares(view types.View, nodeID types.NodeID) []*crypto.PVSSDecryptedShare {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return nil
	}

	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]
	if leaderProposal == nil {
		n.mu.RUnlock()
		return nil
	}

	shareMessages := make(map[types.NodeID]*types.ShareMessage)
	for id, msg := range n.consensus.ShareMessages {
		shareMessages[id] = msg
	}
	n.mu.RUnlock()

	shares := make([]*crypto.PVSSDecryptedShare, 0)
	for senderID, shareMsg := range shareMessages {
		if shareMsg.LeaderID != leaderID {
			continue
		}

		if shareMsg.LeaderShare.Value == nil || shareMsg.DecryptedShare == nil {
			continue
		}

		// Ensure the share matches the sender identity
		if shareMsg.LeaderShare.Recipient != senderID {
			continue
		}

		// Verify encrypted share against leader commitment
		senderInfo := n.participants[senderID]
		if senderInfo == nil {
			continue
		}

		if !n.pvss.Verify(shareMsg.LeaderShare.Index, senderInfo.PVSSPubKey, shareMsg.LeaderShare.Value, leaderProposal.PVSS.Commitment.Coefficients) {
			n.logWarn("Share verification failed, dropping share", "from", senderID)
			continue
		}

		shares = append(shares, &crypto.PVSSDecryptedShare{
			Index: shareMsg.LeaderShare.Index,
			Value: shareMsg.DecryptedShare,
		})
	}

	return shares
}

// determineVote reconstructs the secret and determines the vote
func (n *Node) determineVote(shares []*crypto.PVSSDecryptedShare, view types.View, nodeID types.NodeID) (bool, []byte) {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return false, nil
	}

	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]
	activeCount := len(n.consensus.ActiveNodes)
	n.mu.RUnlock()

	if leaderProposal == nil {
		return false, nil
	}

	threshold := activeCount/2 + 1

	if len(shares) < threshold {
		return false, nil
	}

	// Attempt reconstruction of PVSS secret
	reconstructed, err := n.pvss.Reconstruct(shares)
	if err != nil {
		n.logWarn("Failed to reconstruct PVSS secret", "error", err)
		return false, nil
	}

	if !n.pvss.VerifyReconstruction(reconstructed, leaderProposal.PVSS.SecretHash) {
		n.logWarn("PVSS secret mismatch, voting false")
		return false, nil
	}

	// Verify block hash matches the secret hash
	blockData, _ := json.Marshal(leaderProposal.Block)
	blockHash := crypto.Hash(blockData)

	n.logInfo("Phase3: vote", "vote", "yes", "for_leader", leaderID, "block_height", leaderProposal.Block.Height, "shares", len(shares), "threshold", threshold)

	return true, blockHash
}

// broadcastVoteMessage creates and broadcasts a vote message
func (n *Node) broadcastVoteMessage(view types.View, blockHash []byte, vote bool, nodeID types.NodeID) {
	// Create vote PVSS
	voteData := []byte(fmt.Sprintf("vote:%v:view:%d", vote, view))
	voteHash := crypto.Hash(voteData)
	votePVSS, err := n.createPVSSBundle(voteHash)
	if err != nil {
		n.logError("Failed to create vote PVSS", "error", err)
		return
	}

	// Create vote message
	voteMsg := &types.VoteMessage{
		View:      view,
		BlockHash: blockHash,
		Vote:      vote,
		VotePVSS:  *votePVSS,
	}

	msgData, _ := json.Marshal(voteMsg)
	sig, _ := n.signer.Sign(msgData)
	voteMsg.Signature = sig

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgVote, voteMsg)

	// Store vote
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Votes[nodeID] = voteMsg
	}
	n.mu.Unlock()
}

// countVotes counts valid votes and returns the vote count and decided hash
func (n *Node) countVotes() (int, []byte) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.consensus == nil {
		return 0, nil
	}

	voteCount := 0
	var decidedHash []byte

	for _, voteMsg := range n.consensus.Votes {
		if voteMsg.Vote {
			voteCount++
			if decidedHash == nil {
				decidedHash = voteMsg.BlockHash
			}
		}
	}

	return voteCount, decidedHash
}

// broadcastConfirmIfQuorum broadcasts a confirmation message if vote quorum is reached
func (n *Node) broadcastConfirmIfQuorum(view types.View, decidedHash []byte, voteCount int, nodeID types.NodeID) {
	n.mu.RLock()
	if n.consensus == nil {
		n.mu.RUnlock()
		return
	}

	leaderProposal := n.consensus.Proposals[n.consensus.LeaderID]
	activeCount := len(n.consensus.ActiveNodes)
	quorum := activeCount / 2
	n.mu.RUnlock()

	if voteCount < quorum || leaderProposal == nil {
		return
	}

	// Create confirmation message
	confirmMsg := &types.ConfirmMessage{
		View:      view,
		BlockHash: decidedHash,
	}

	msgData, _ := json.Marshal(confirmMsg)
	sig, _ := n.signer.Sign(msgData)
	confirmMsg.Signature = sig

	n.logInfo("Phase4: confirm", "for_leader", leaderProposal.Block.Proposer, "block_height", leaderProposal.Block.Height, "votes", voteCount, "quorum", quorum)

	n.mu.RLock()
	broadcastCtx := n.ctx
	n.mu.RUnlock()

	n.broadcast(broadcastCtx, types.MsgConfirm, confirmMsg)

	// Store confirm
	n.mu.Lock()
	if n.consensus != nil {
		n.consensus.Confirms[nodeID] = confirmMsg
	}
	n.mu.Unlock()
}

func (n *Node) createBlock(view types.View) *types.Block {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Get transactions from pool
	txs := make([]types.Transaction, 0)
	if len(n.txPool) > 0 {
		count := len(n.txPool)
		if count > DefaultMaxTransactionsPerBlock {
			count = DefaultMaxTransactionsPerBlock
		}
		txs = n.txPool[:count]
		n.txPool = n.txPool[count:]
	}

	latest := n.chain.Latest()
	var parentHash []byte
	var height uint64
	if latest != nil {
		parentHash = latest.Hash
		height = latest.Height + 1
	}

	block := &types.Block{
		View:         view,
		Height:       height,
		ParentHash:   parentHash,
		Transactions: txs,
		Proposer:     n.config.NodeID,
		Timestamp:    time.Now(),
	}

	// Compute block hash
	blockData, _ := json.Marshal(block)
	block.Hash = crypto.Hash(blockData)

	return block
}

func (n *Node) createPVSSBundle(secret []byte) (*types.PVSSBundle, error) {
	n.mu.RLock()
	participants := make([]*Participant, 0, len(n.participants))
	for _, p := range n.participants {
		if p.IsActive {
			participants = append(participants, p)
		}
	}
	nodeID := n.config.NodeID
	n.mu.RUnlock()

	if len(participants) == 0 {
		return nil, fmt.Errorf("no active participants")
	}

	// Collect public keys
	publicKeys := make([]*big.Int, len(participants))
	for i, p := range participants {
		publicKeys[i] = p.PVSSPubKey
	}

	// Calculate threshold
	threshold := len(participants)/2 + 1

	// Create PVSS shares
	secretInt := crypto.HashToBigInt(secret, n.pvss.Q)
	_, publicData, err := n.pvss.Split(secretInt, publicKeys, threshold)
	if err != nil {
		return nil, err
	}

	// Create share structs
	shares := make([]types.PVSSShare, len(participants))
	for i, p := range participants {
		shares[i] = types.PVSSShare{
			Index:     i + 1,
			Value:     publicData.EncryptedShares[i],
			Recipient: p.ID,
		}
	}

	// Create commitment
	commitment := types.PVSSCommitment{
		Coefficients: publicData.Commitments,
	}

	return &types.PVSSBundle{
		DealerID:   nodeID,
		Shares:     shares,
		Commitment: commitment,
		SecretHash: secret,
	}, nil
}

func (n *Node) broadcast(ctx context.Context, msgType types.MessageType, payload interface{}) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	msg := &types.Message{
		Type:      msgType,
		From:      n.config.NodeID,
		Timestamp: time.Now(),
		Payload:   payload,
	}
	n.network.Broadcast(ctx, msg)
}

// verifySignatureForMessage clones msg, removes the signature field via clearSig, and verifies it.
func verifySignatureForMessage[T any](msg *T, pub *ecdsa.PublicKey, clearSig func(*T) []byte) bool {
	if msg == nil || pub == nil {
		return false
	}

	msgCopy := *msg
	sig := clearSig(&msgCopy)
	data, err := json.Marshal(&msgCopy)
	if err != nil {
		return false
	}
	return crypto.Verify(pub, data, sig)
}

func (n *Node) getAwakeList() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	list := make([]types.NodeID, 0)
	for id, p := range n.participants {
		if p.IsActive {
			list = append(list, id)
		}
	}
	return list
}

func (n *Node) getNextRoundCommits() []types.NodeID {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.consensus == nil {
		return nil
	}

	list := make([]types.NodeID, 0)
	for id := range n.consensus.NextRoundCommits {
		list = append(list, id)
	}
	return list
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
