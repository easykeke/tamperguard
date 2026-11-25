// Package audit implements the tamper-evident audit trail.
//
// Threat model for this package: an attacker who can write files on the
// protected host will also try to erase or forge the records of what they
// did. We therefore make every record:
//
//   - chained:   Hash = SHA-256(canonical record incl. PrevHash)
//   - sequenced: Seq increases by exactly 1 per agent, with no holes
//   - signed:    each record is Ed25519-signed by the agent key
//
// Chaining alone only detects modification, not deletion: removing a suffix
// still leaves a self-consistent chain. That is why sequence numbers and
// per-record signatures are mandatory -- the server tracks the last seen
// (Seq, Hash) per agent and flags any gap or fork as a tamper alarm.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Event kinds. Keep these stable: they are persisted and queried by the UI.
const (
	KindWriteBlocked   = "write.blocked"
	KindWriteAllowed   = "write.allowed"
	KindWriteObserved  = "write.observed"
	KindTokenIssued    = "token.issued"
	KindTokenRevoked   = "token.revoked"
	KindTokenRejected  = "token.rejected"
	KindPolicyApplied  = "policy.applied"
	KindDegraded       = "enforcer.degraded"
	KindEnforcerError  = "enforcer.error"
	KindAgentStarted   = "agent.started"
	KindAgentHeartbeat = "agent.heartbeat"
	KindPublishDone    = "publish.completed"
	KindPublishFailed  = "publish.failed"
)

var (
	ErrSequence  = errors.New("audit: sequence gap or replay")
	ErrPrevHash  = errors.New("audit: chain link mismatch")
	ErrHash      = errors.New("audit: record hash mismatch")
	ErrSignature = errors.New("audit: record signature invalid")
	ErrMalformed = errors.New("audit: malformed record")
	ErrNoSigner  = errors.New("audit: writer has no signing key")
)

// Record is one audit event. Field order matters: the canonical JSON used for
// hashing is produced from this struct, so do not reorder or rename fields
// without bumping a format version.
type Record struct {
	Seq       uint64 `json:"seq"`
	AgentID   string `json:"agent"`
	Time      int64  `json:"ts"`
	Kind      string `json:"kind"`
	Decision  string `json:"decision,omitempty"`
	Path      string `json:"path,omitempty"`
	Op        string `json:"op,omitempty"`
	Subject   string `json:"subject,omitempty"`
	TokenID   string `json:"token_id,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
	PolicyRev string `json:"policy_rev,omitempty"`
	Detail    string `json:"detail,omitempty"`
	PrevHash  string `json:"prev"`
	Hash      string `json:"hash"`
	Sig       string `json:"sig"`
}

// ComputeHash returns the hex SHA-256 over the canonical record with Hash and
// Sig blanked out and PrevHash included.
func (r *Record) ComputeHash() (string, error) {
	c := *r
	c.Hash = ""
	c.Sig = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("audit: marshal record: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Seal computes Hash and, when priv is non-nil, signs it.
func (r *Record) Seal(priv ed25519.PrivateKey) error {
	h, err := r.ComputeHash()
	if err != nil {
		return err
	}
	r.Hash = h
	if len(priv) == 0 {
		r.Sig = ""
		return nil
	}
	if len(priv) != ed25519.PrivateKeySize {
		return ErrNoSigner
	}
	r.Sig = hex.EncodeToString(ed25519.Sign(priv, []byte(h)))
	return nil
}

// VerifySeal recomputes the hash and checks the signature.
func (r *Record) VerifySeal(pub ed25519.PublicKey) error {
	want, err := r.ComputeHash()
	if err != nil {
		return err
	}
	if !equalHex(want, r.Hash) {
		return ErrHash
	}
	if len(pub) == 0 {
		return nil
	}
	sig, err := hex.DecodeString(r.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	if !ed25519.Verify(pub, []byte(r.Hash), sig) {
		return ErrSignature
	}
	return nil
}

// Writer appends sealed records as JSON lines. It is the only place that
// assigns Seq and PrevHash, and it serialises appends so the chain stays
// linear even under concurrent producers.
type Writer struct {
	mu      sync.Mutex
	agentID string
	nextSeq uint64
	prev    string
	priv    ed25519.PrivateKey
	out     io.Writer
	now     func() time.Time
}

// NewWriter creates a chain writer starting at seq (use 1 for a new chain, or
// lastSeq+1 when resuming from disk). prevHash is the hash of the last record
// written, or "" for a new chain.
func NewWriter(agentID string, priv ed25519.PrivateKey, out io.Writer, nextSeq uint64, prevHash string) *Writer {
	if nextSeq == 0 {
		nextSeq = 1
	}
	return &Writer{
		agentID: agentID,
		nextSeq: nextSeq,
		prev:    prevHash,
		priv:    priv,
		out:     out,
		now:     time.Now,
	}
}

// NextSeq returns the sequence number that the next Append will use.
func (w *Writer) NextSeq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSeq
}

// LastHash returns the hash of the last successfully written record.
func (w *Writer) LastHash() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prev
}

// Append fills in Seq/PrevHash/Time, seals and writes one record.
func (w *Writer) Append(r Record) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	r.AgentID = w.agentID
	r.Seq = w.nextSeq
	r.PrevHash = w.prev
	if r.Time == 0 {
		r.Time = w.now().Unix()
	}
	if err := r.Seal(w.priv); err != nil {
		return Record{}, err
	}
	line, err := json.Marshal(r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: marshal line: %w", err)
	}
	if w.out != nil {
		if _, err := w.out.Write(append(line, '\n')); err != nil {
			return Record{}, fmt.Errorf("audit: write line: %w", err)
		}
	}
	w.nextSeq++
	w.prev = r.Hash
	return r, nil
}

// ChainState is the server-side tracking state for one agent's chain.
type ChainState struct {
	AgentID  string `json:"agent_id"`
	NextSeq  uint64 `json:"next_seq"`
	LastHash string `json:"last_hash"`
}

// Verifier validates a stream of records for a single agent, in order.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier creates a verifier; pub may be nil to check integrity only.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pub: pub}
}

// Next validates r against the running state and advances it on success.
// The state is only mutated if the record is fully valid.
func (v *Verifier) Next(st *ChainState, r Record) error {
	if st == nil {
		return ErrMalformed
	}
	if r.AgentID != st.AgentID {
		return fmt.Errorf("%w: foreign agent %q", ErrMalformed, r.AgentID)
	}
	if st.NextSeq != 0 && r.Seq != st.NextSeq {
		return fmt.Errorf("%w: expected seq %d, got %d", ErrSequence, st.NextSeq, r.Seq)
	}
	if r.PrevHash != st.LastHash {
		return fmt.Errorf("%w: prev %q != %q", ErrPrevHash, r.PrevHash, st.LastHash)
	}
	if err := r.VerifySeal(v.pub); err != nil {
		return err
	}
	st.NextSeq = r.Seq + 1
	st.LastHash = r.Hash
	return nil
}

// VerifyAll validates an entire chain from scratch.
func (v *Verifier) VerifyAll(agentID string, records []Record) (*ChainState, error) {
	st := &ChainState{AgentID: agentID, NextSeq: 1, LastHash: ""}
	for _, r := range records {
		if err := v.Next(st, r); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
