package enforcer

import (
	"errors"
	"sync"

	"github.com/easykeke/tamperguard/internal/policy"
)

// Sim is a userspace-only enforcer. It enforces nothing; it exists so the
// control plane, token flow and audit chain can be exercised on hosts without
// kernel support (and in unit tests).
//
// It reports Degraded=true on purpose: a node running this must never be
// counted as compliant in the UI.
type Sim struct {
	mu     sync.RWMutex
	rt     Runtime
	events *Buffer
}

// NewSim creates a simulation enforcer.
func NewSim() *Sim {
	return &Sim{events: NewBuffer(256)}
}

// Name implements Enforcer.
func (s *Sim) Name() string { return "observe" }

// Capability implements Enforcer.
func (s *Sim) Capability() Capability {
	return Capability{
		Kind:      "observe",
		Available: true,
		Degraded:  true,
		Reason:    "userspace only: decisions are logged, writes are not blocked",
	}
}

// Update implements Enforcer.
func (s *Sim) Update(rt Runtime) error {
	s.mu.Lock()
	s.rt = rt
	s.mu.Unlock()
	return nil
}

// Probe evaluates a write request against the current runtime and emits the
// resulting event. Tests and the `tg-agent check-write` helper use it.
func (s *Sim) Probe(req policy.Request) policy.Decision {
	s.mu.RLock()
	rt := s.rt
	s.mu.RUnlock()
	d := rt.Decide(req)
	tokenID := ""
	for _, g := range rt.ValidGrants(req.Subject.ID, req.NodeID, req.Now) {
		if d.Reason == policy.ReasonGranted {
			tokenID = g.TokenID
			break
		}
	}
	s.events.Emit(EventFromDecision(req, d, tokenID))
	return d
}

// Events implements Enforcer.
func (s *Sim) Events() <-chan Event { return s.events.Events() }

// Health implements Enforcer.
func (s *Sim) Health() error { return nil }

// Close implements Enforcer.
func (s *Sim) Close() error {
	s.events.Close()
	return nil
}

// ErrNoBackend is returned when no enforcer could be built on this host.
var ErrNoBackend = errors.New("enforcer: no usable enforcement backend on this host")
