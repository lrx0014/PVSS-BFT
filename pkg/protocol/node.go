package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	log "log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/lrx0014/pvss-bft/pkg/crypto"
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
		ViewDuration: 4 * delta,
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

	n.logger.Info("Start view",
		"node_id", n.config.NodeID,
		"view", view,
		"active_nodes", len(n.consensus.ActiveNodes))

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

	n.logger.Info("Advance phase",
		"node_id", n.config.NodeID,
		"view", n.currentView,
		"phase", phase)

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

	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
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
		n.logger.Error("Failed to create PVSS bundle",
			"node_id", nodeID,
			"view", view,
			"error", err)
		return
	}

	// generate VRF output
	vrfInput := []byte(fmt.Sprintf("view:%d", view))
	vrfProof, err := n.vrf.Evaluate(n.vrfKey.PrivateKey, vrfInput)
	if err != nil {
		n.logger.Error("Failed to generate VRF",
			"node_id", nodeID,
			"view", view,
			"error", err)
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

	n.logger.Info("Phase1 propose",
		"node_id", nodeID,
		"view", view,
		"vrf", fmt.Sprintf("%x", vrfProof.Output))

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
	n.mu.Lock()
	if n.consensus == nil {
		n.mu.Unlock()
		return
	}
	ctx := n.ctx

	// verify proposals and elect leader
	var leaderID types.NodeID
	var maxVRF []byte

	validProposals := make(map[types.NodeID]*types.ProposeMessage)

	for id, proposal := range n.consensus.Proposals {
		// verify VRF
		participant := n.participants[id]
		if participant == nil {
			continue
		}

		vrfInput := []byte(fmt.Sprintf("view:%d", n.currentView))
		vrfProof := &crypto.VRFProof{
			Output: proposal.VRF.Value,
			Proof:  proposal.VRF.Proof,
		}

		valid, _ := n.vrf.Verify(participant.VRFPubKey, vrfInput, vrfProof)
		if !valid {
			continue
		}

		// TODO: verify PVSS shares (simplified - in production, verify each share)
		// but for now, just check that shares exist
		if len(proposal.PVSS.Shares) == 0 {
			continue
		}

		validProposals[id] = proposal

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
	nodeID := n.config.NodeID
	view := n.currentView
	n.mu.Unlock()

	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	if leaderID == "" {
		n.logger.Warn("No valid leader found",
			"node_id", nodeID,
			"view", view)
		return
	}

	n.logger.Info("Phase2 leader elected",
		"node_id", nodeID,
		"view", view,
		"leader", leaderID,
		"leader_vrf", fmt.Sprintf("%x", maxVRF))

	// Get share of the leader's PVSS
	n.mu.RLock()
	leaderProposal := n.consensus.Proposals[leaderID]
	n.mu.RUnlock()

	if leaderProposal == nil {
		return
	}

	// Find share from leader
	var ourShare types.PVSSShare
	for _, share := range leaderProposal.PVSS.Shares {
		if share.Recipient == nodeID {
			ourShare = share
			break
		}
	}

	// Verify if encrypted share matches leader commitment
	participant := n.participants[nodeID]
	if participant == nil {
		n.logger.Warn("Missing participant info for share verification",
			"node_id", nodeID,
			"view", view)
		return
	}

	if !n.pvss.Verify(ourShare.Index, participant.PVSSPubKey, ourShare.Value, leaderProposal.PVSS.Commitment.Coefficients) {
		n.logger.Warn("Share verification failed, not broadcasting share message",
			"node_id", nodeID,
			"view", view)
		return
	}

	// Decrypt the share for others to reconstruct
	decrypted := n.pvss.DecryptShare(ourShare.Value, n.pvssPriv)
	if decrypted == nil {
		n.logger.Warn("Failed to decrypt share, not broadcasting share message",
			"node_id", nodeID,
			"view", view)
		return
	}

	// Create share message
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

// executePhase3 executes Phase 3: Secret Reconstruction and Voting
func (n *Node) executePhase3() {
	n.mu.Lock()
	if n.consensus == nil {
		n.mu.Unlock()
		return
	}
	ctx := n.ctx
	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]
	view := n.currentView
	nodeID := n.config.NodeID
	activeCount := len(n.consensus.ActiveNodes)

	if leaderProposal == nil {
		n.mu.Unlock()
		return
	}

	// Collect shares for reconstruction
	shares := make([]*crypto.PVSSDecryptedShare, 0)
	for senderID, shareMsg := range n.consensus.ShareMessages {
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
			n.logger.Warn("Share verification failed; dropping share",
				"node_id", nodeID,
				"view", view,
				"from", senderID)
			continue
		}

		shares = append(shares, &crypto.PVSSDecryptedShare{
			Index: shareMsg.LeaderShare.Index,
			Value: shareMsg.DecryptedShare,
		})
	}
	n.mu.Unlock()

	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	// Determine vote
	vote := false
	var blockHash []byte

	if leaderProposal != nil {
		threshold := activeCount/2 + 1

		if len(shares) >= threshold {
			// Attempt reconstruction of PVSS secret
			reconstructed, err := n.pvss.Reconstruct(shares)
			if err != nil {
				n.logger.Warn("Failed to reconstruct PVSS secret",
					"node_id", nodeID,
					"view", view,
					"error", err)
			} else if n.pvss.VerifyReconstruction(reconstructed, leaderProposal.PVSS.SecretHash) {
				// Verify block hash matches the secret hash
				blockData, _ := json.Marshal(leaderProposal.Block)
				blockHash = crypto.Hash(blockData)
				vote = true
				n.logger.Info("Phase3 vote true",
					"node_id", nodeID,
					"view", view,
					"shares", len(shares),
					"threshold", threshold)
			} else {
				n.logger.Warn("Reconstructed PVSS secret mismatch; voting false",
					"node_id", nodeID,
					"view", view)
			}
		}
	}

	// TODO: Create vote PVSS
	// (simplified with just hash of vote)
	voteData := []byte(fmt.Sprintf("vote:%v:view:%d", vote, view))
	voteHash := crypto.Hash(voteData)
	votePVSS, err := n.createPVSSBundle(voteHash)
	if err != nil {
		n.logger.Error("Failed to create vote PVSS",
			"node_id", nodeID,
			"view", view,
			"error", err)
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

// executePhase4 executes Phase 4: Confirmation and Consensus
func (n *Node) executePhase4() {
	n.mu.Lock()
	if n.consensus == nil {
		n.mu.Unlock()
		return
	}
	ctx := n.ctx
	view := n.currentView
	nodeID := n.config.NodeID
	leaderID := n.consensus.LeaderID
	leaderProposal := n.consensus.Proposals[leaderID]

	// Count valid votes
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

	// Check if we have quorum
	activeCount := len(n.consensus.ActiveNodes)
	quorum := activeCount / 2

	n.mu.Unlock()

	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	if voteCount >= quorum && leaderProposal != nil {
		// confirm message
		confirmMsg := &types.ConfirmMessage{
			View:      view,
			BlockHash: decidedHash,
		}

		msgData, _ := json.Marshal(confirmMsg)
		sig, _ := n.signer.Sign(msgData)
		confirmMsg.Signature = sig

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

	// Check for decision (if we have enough confirms)
	n.mu.Lock()
	confirmCount := 0
	for _, confirmMsg := range n.consensus.Confirms {
		if bytes.Equal(confirmMsg.BlockHash, decidedHash) {
			confirmCount++
		}
	}

	if confirmCount >= quorum && leaderProposal != nil {
		// Decide on the block
		block := leaderProposal.Block
		block.Hash = decidedHash
		n.consensus.DecidedBlock = &block
		n.logger.Info("Decided on block",
			"node_id", nodeID,
			"view", view,
			"leader", leaderID,
			"block_height", block.Height)
	}
	n.mu.Unlock()
}

// Message handlers

func (n *Node) handlePropose(msg *types.Message) {
	proposeMsg, ok := msg.Payload.(*types.ProposeMessage)
	if !ok {
		// try to unmarshal from msg
		data, _ := json.Marshal(msg.Payload)
		proposeMsg = &types.ProposeMessage{}
		if err := json.Unmarshal(data, proposeMsg); err != nil {
			return
		}
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !verifySignatureForMessage(proposeMsg, participant.PublicKey, func(p *types.ProposeMessage) []byte {
		sig := p.Signature
		p.Signature = nil
		return sig
	}) {
		return
	}

	// Verify VRF output
	vrfInput := []byte(fmt.Sprintf("view:%d", proposeMsg.View))
	vrfProof := &crypto.VRFProof{
		Output: proposeMsg.VRF.Value,
		Proof:  proposeMsg.VRF.Proof,
	}
	validVRF, _ := n.vrf.Verify(participant.VRFPubKey, vrfInput, vrfProof)
	if !validVRF {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil || proposeMsg.View != n.currentView {
		return
	}

	// Store proposal
	n.consensus.Proposals[msg.From] = proposeMsg
}

func (n *Node) handleShare(msg *types.Message) {
	shareMsg, ok := msg.Payload.(*types.ShareMessage)
	if !ok {
		data, _ := json.Marshal(msg.Payload)
		shareMsg = &types.ShareMessage{}
		if err := json.Unmarshal(data, shareMsg); err != nil {
			return
		}
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !verifySignatureForMessage(shareMsg, participant.PublicKey, func(s *types.ShareMessage) []byte {
		sig := s.Signature
		s.Signature = nil
		return sig
	}) {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil || shareMsg.View != n.currentView {
		return
	}

	// Store share message
	n.consensus.ShareMessages[msg.From] = shareMsg
	n.consensus.AwakeLists[msg.From] = shareMsg.AwakeList
}

func (n *Node) handleVote(msg *types.Message) {
	voteMsg, ok := msg.Payload.(*types.VoteMessage)
	if !ok {
		data, _ := json.Marshal(msg.Payload)
		voteMsg = &types.VoteMessage{}
		if err := json.Unmarshal(data, voteMsg); err != nil {
			return
		}
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !verifySignatureForMessage(voteMsg, participant.PublicKey, func(v *types.VoteMessage) []byte {
		sig := v.Signature
		v.Signature = nil
		return sig
	}) {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil || voteMsg.View != n.currentView {
		return
	}

	// Store vote
	n.consensus.Votes[msg.From] = voteMsg
}

func (n *Node) handleConfirm(msg *types.Message) {
	confirmMsg, ok := msg.Payload.(*types.ConfirmMessage)
	if !ok {
		data, _ := json.Marshal(msg.Payload)
		confirmMsg = &types.ConfirmMessage{}
		if err := json.Unmarshal(data, confirmMsg); err != nil {
			return
		}
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !verifySignatureForMessage(confirmMsg, participant.PublicKey, func(c *types.ConfirmMessage) []byte {
		sig := c.Signature
		c.Signature = nil
		return sig
	}) {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.consensus == nil || confirmMsg.View != n.currentView {
		return
	}

	// Store confirm
	n.consensus.Confirms[msg.From] = confirmMsg

	// Check if we can decide
	decidedHash := confirmMsg.BlockHash
	confirmCount := 0
	for _, cm := range n.consensus.Confirms {
		if bytes.Equal(cm.BlockHash, decidedHash) {
			confirmCount++
		}
	}

	activeCount := len(n.consensus.ActiveNodes)
	quorum := activeCount / 2

	if confirmCount >= quorum && n.consensus.DecidedBlock == nil {
		leaderProposal := n.consensus.Proposals[n.consensus.LeaderID]
		if leaderProposal != nil {
			block := leaderProposal.Block
			block.Hash = decidedHash
			n.consensus.DecidedBlock = &block
			n.logger.Info("Decided on block",
				"node_id", n.config.NodeID,
				"view", confirmMsg.View,
				"leader", n.consensus.LeaderID,
				"block_height", block.Height)
		}
	}
}

func (n *Node) handleAwake(msg *types.Message) {
	awakeMsg, ok := msg.Payload.(*types.AwakeMessage)
	if !ok {
		data, _ := json.Marshal(msg.Payload)
		awakeMsg = &types.AwakeMessage{}
		if err := json.Unmarshal(data, awakeMsg); err != nil {
			return
		}
	}

	participant := n.participants[msg.From]
	if participant == nil {
		return
	}

	if !verifySignatureForMessage(awakeMsg, participant.PublicKey, func(a *types.AwakeMessage) []byte {
		sig := a.Signature
		a.Signature = nil
		return sig
	}) {
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

func (n *Node) createBlock(view types.View) *types.Block {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Get transactions from pool
	txs := make([]types.Transaction, 0)
	if len(n.txPool) > 0 {
		// only take up to 100 transactions for performance reasons
		count := len(n.txPool)
		if count > 100 {
			count = 100
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
