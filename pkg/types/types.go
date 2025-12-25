package types

import (
	"crypto/ecdsa"
	"math/big"
	"sync"
	"time"
)

type View uint64

type NodeID string

type Transaction struct {
	ID        string    `json:"id"`
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	Sender    NodeID    `json:"sender"`
}

type Block struct {
	View         View          `json:"view"`
	Height       uint64        `json:"height"`
	ParentHash   []byte        `json:"parent_hash"`
	Transactions []Transaction `json:"transactions"`
	Proposer     NodeID        `json:"proposer"`
	Timestamp    time.Time     `json:"timestamp"`
	Hash         []byte        `json:"hash"` // Computed hash of the block
}

type PreCommit struct {
	NodeID       NodeID `json:"node_id"`
	View         View   `json:"view"`           // Current view
	NextViewJoin bool   `json:"next_view_join"` // Whether node intends to join next view
	Signature    []byte `json:"signature"`
}

type PVSSShare struct {
	Index     int      `json:"index"`     // Share index (1 to n)
	Value     *big.Int `json:"value"`     // Encrypted share value Y_i = y_i^p(i)
	Recipient NodeID   `json:"recipient"` // Intended recipient
}

type PVSSCommitment struct {
	Coefficients []*big.Int `json:"coefficients"` // C_j = g^a_j for j = 0 to t-1
}

type PVSSBundle struct {
	DealerID   NodeID         `json:"dealer_id"`
	Shares     []PVSSShare    `json:"shares"`
	Commitment PVSSCommitment `json:"commitment"`
	SecretHash []byte         `json:"secret_hash"` // Hash being shared
}

type VRFOutput struct {
	Value []byte `json:"value"` // Pseudo-random output ρ
	Proof []byte `json:"proof"` // Proof pi
}

type ProposeMessage struct {
	View      View       `json:"view"`
	Block     Block      `json:"block"`
	PVSS      PVSSBundle `json:"pvss"`
	VRF       VRFOutput  `json:"vrf"`
	PreCommit PreCommit  `json:"precommit"`
	Signature []byte     `json:"signature"`
}

type ShareMessage struct {
	View            View      `json:"view"`
	LeaderID        NodeID    `json:"leader_id"`
	LeaderShare     PVSSShare `json:"leader_share"`      // Share received from leader
	AwakeList       []NodeID  `json:"awake_list"`        // Nodes observed as awake
	NextRoundCommit []NodeID  `json:"next_round_commit"` // Nodes committing to next round
	Signature       []byte    `json:"signature"`
}

type VoteMessage struct {
	View      View       `json:"view"`
	BlockHash []byte     `json:"block_hash"`
	Vote      bool       `json:"vote"`      // true = valid, false = invalid
	VotePVSS  PVSSBundle `json:"vote_pvss"` // PVSS encoding of the vote
	Signature []byte     `json:"signature"`
}

type ConfirmMessage struct {
	View      View   `json:"view"`
	BlockHash []byte `json:"block_hash"`
	Signature []byte `json:"signature"`
}

type AwakeMessage struct {
	NodeID    NodeID    `json:"node_id"`
	View      View      `json:"view"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`
}

type MessageType int

const (
	MsgPropose MessageType = iota
	MsgShare
	MsgVote
	MsgConfirm
	MsgAwake
)

type Message struct {
	Type      MessageType `json:"type"`
	From      NodeID      `json:"from"`
	Timestamp time.Time   `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

type NodeState int

const (
	StateAwake NodeState = iota
	StateSleepy
)

type Phase int

const (
	PhasePropose Phase = iota // Phase 1: Block Proposal and Share Distribution
	PhaseShare                // Phase 2: Share Verification and Leader Election
	PhaseVote                 // Phase 3: Secret Reconstruction and Voting
	PhaseConfirm              // Phase 4: Confirmation and Consensus
)

type NodeInfo struct {
	ID        NodeID           `json:"id"`
	PublicKey *ecdsa.PublicKey `json:"-"`
	PVSSKey   *big.Int         `json:"pvss_key"` // Public key for PVSS: y_i = G^x_i
	Address   string           `json:"address"`  // Network address
}

// ConsensusState tracks the state of consensus for a view
type ConsensusState struct {
	mu sync.RWMutex

	View        View
	Phase       Phase
	ActiveNodes map[NodeID]bool

	// Phase 1 data
	Proposals map[NodeID]*ProposeMessage

	// Phase 2 data
	LeaderID      NodeID
	LeaderVRF     []byte
	ShareMessages map[NodeID]*ShareMessage
	AwakeLists    map[NodeID][]NodeID

	// Phase 3 data
	CollectedShares []PVSSShare
	Votes           map[NodeID]*VoteMessage

	// Phase 4 data
	Confirms map[NodeID]*ConfirmMessage

	// Decided block
	DecidedBlock *Block

	// Next round tracking
	NextRoundCommits map[NodeID]bool
	NewAwakeNodes    map[NodeID]bool
}

// NewConsensusState creates a new consensus state for a view
func NewConsensusState(view View) *ConsensusState {
	return &ConsensusState{
		View:             view,
		Phase:            PhasePropose,
		ActiveNodes:      make(map[NodeID]bool),
		Proposals:        make(map[NodeID]*ProposeMessage),
		ShareMessages:    make(map[NodeID]*ShareMessage),
		AwakeLists:       make(map[NodeID][]NodeID),
		CollectedShares:  make([]PVSSShare, 0),
		Votes:            make(map[NodeID]*VoteMessage),
		Confirms:         make(map[NodeID]*ConfirmMessage),
		NextRoundCommits: make(map[NodeID]bool),
		NewAwakeNodes:    make(map[NodeID]bool),
	}
}

// Chain contains the blockchain
type Chain struct {
	mu     sync.RWMutex
	Blocks []*Block
}

func NewChain() *Chain {
	genesis := &Block{
		View:         0,
		Height:       0,
		ParentHash:   nil,
		Transactions: nil,
		Proposer:     "genesis",
		Timestamp:    time.Now(),
		Hash:         []byte("genesis"),
	}
	return &Chain{
		Blocks: []*Block{genesis},
	}
}

func (c *Chain) Append(block *Block) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Blocks = append(c.Blocks, block)
}

func (c *Chain) Latest() *Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.Blocks) == 0 {
		return nil
	}
	return c.Blocks[len(c.Blocks)-1]
}

func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(len(c.Blocks) - 1)
}
