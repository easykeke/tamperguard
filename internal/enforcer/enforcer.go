// Package enforcer defines the boundary between policy logic and the kernel.
//
// The same decision function (policy.Decide) is used by every enforcer:
//   - the eBPF LSM enforcer blocks synchronously in the kernel;
//   - the fanotify enforcer detects and restores after the fact;
//   - the sim enforcer exists so the whole pipeline can be exercised on any OS.
//
// Keeping the decision in one place is what makes the three modes comparable
// in tests: a write blocked by eBPF and a write flagged by fanotify must
// produce the same audit record.
package enforcer

import (
	"sync"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/policy"
)

// Capability describes what an enforcer can actually do on this host.
type Capability struct {
	Kind      string `json:"kind"`      // ebpf-lsm | fanotify | observe
	Available bool   `json:"available"` // can it enforce at all
	Degraded  bool   `json:"degraded"`  // available, but weaker than the target
	Reason    string `json:"reason,omitempty"`
}

// RevocationSet is the flattened revocation list delivered by the control
// plane. Keys are "<kind>:<value>".
type RevocationSet map[string]bool

// Has reports whether a revocation entry exists.
func (r RevocationSet) Has(kind, value string) bool {
	if r == nil {
		return false
	}
	return r[kind+":"+value]
}

// Runtime is the complete, immutable state an enforcer needs to decide.
// It is swapped atomically on every policy sync.
type Runtime struct {
	Policy      *policy.Snapshot
	Grants      []policy.Grant
	Revocations RevocationSet
	UpdatedAt   int64
}

// ValidGrants filters the grant list down to the ones that authorise subject
// right now, dropping expired and revoked entries.
func (rt Runtime) ValidGrants(subjectID, nodeID string, now int64) []policy.Grant {
	out := make([]policy.Grant, 0, len(rt.Grants))
	for _, g := range rt.Grants {
		if g.Subject != "" && subjectID != "" && g.Subject != subjectID {
			continue
		}
		if nodeID != "" && g.NodeID != "" && g.NodeID != nodeID {
			continue
		}
		if g.ExpiresAt != 0 && g.ExpiresAt <= now {
			continue
		}
		if rt.Revocations.Has("token", g.TokenID) || rt.Revocations.Has("subject", g.Subject) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// Decide is the shared decision entry point.
func (rt Runtime) Decide(req policy.Request) policy.Decision {
	if rt.Policy == nil {
		return policy.Decision{Allow: true, Reason: "no-policy"}
	}
	req.Grants = rt.ValidGrants(req.Subject.ID, req.NodeID, req.Now)
	return rt.Policy.Policy.Decide(req)
}

// Event is one enforcement outcome, ready to be sealed into the audit chain.
type Event struct {
	Time    int64
	Kind    string
	Path    string
	Op      policy.Op
	Subject policy.Subject
	TokenID string
	Rule    string
	Reason  string
}

// Enforcer is implemented by every enforcement backend.
type Enforcer interface {
	// Name returns the backend name: ebpf-lsm, fanotify or observe.
	Name() string
	// Capability reports what this backend can do here and now.
	Capability() Capability
	// Update atomically replaces the runtime state.
	Update(rt Runtime) error
	// Events streams enforcement outcomes for auditing.
	Events() <-chan Event
	// Health returns non-nil when enforcement silently stopped working,
	// which is the most dangerous failure mode of any kernel-based control.
	Health() error
	// Close releases kernel resources.
	Close() error
}

// Buffer is a small fan-out helper shared by the backends.
type Buffer struct {
	mu     sync.Mutex
	ch     chan Event
	closed bool
}

// NewBuffer creates an event buffer with the given depth.
func NewBuffer(depth int) *Buffer {
	if depth <= 0 {
		depth = 256
	}
	return &Buffer{ch: make(chan Event, depth)}
}

// Emit enqueues an event, dropping it if the consumer is too slow. Dropping
// is reported by the caller's Health() path via a counter, not silently.
func (b *Buffer) Emit(ev Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	select {
	case b.ch <- ev:
		return true
	default:
		return false
	}
}

// Events returns the receive side.
func (b *Buffer) Events() <-chan Event { return b.ch }

// Close stops accepting events.
func (b *Buffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	close(b.ch)
}

// EventFromDecision converts a decision into an audit-ready event.
func EventFromDecision(req policy.Request, d policy.Decision, tokenID string) Event {
	kind := audit.KindWriteBlocked
	switch {
	case d.Reason == policy.ReasonNotProtected:
		kind = audit.KindWriteAllowed
	case d.Mode == policy.ModeObserve || d.Reason == policy.ReasonObserve:
		kind = audit.KindWriteObserved
	case d.Allow:
		kind = audit.KindWriteAllowed
	}
	return Event{
		Time:    time.Now().Unix(),
		Kind:    kind,
		Path:    req.Path,
		Op:      req.Op,
		Subject: req.Subject,
		TokenID: tokenID,
		Rule:    d.Rule,
		Reason:  d.Reason,
	}
}
