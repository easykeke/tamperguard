package server

import (
	"encoding/json"
	"sync"
	"time"
)

// Event kinds pushed over the agent stream.
const (
	EventPolicy    = "policy"
	EventRevoke    = "revoke"
	EventGrant     = "grant"
	EventUninstall = "uninstall"
)

// Event is a lightweight nudge: it tells the agent that something changed and
// it should sync now. The authoritative state always comes from the heartbeat
// response, so a dropped event costs latency, never correctness.
type Event struct {
	Kind    string          `json:"kind"`
	NodeID  string          `json:"node_id,omitempty"`
	At      int64           `json:"at"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type subscriber struct {
	ch chan Event
}

// Hub fans out change notifications to connected agents.
//
// Delivery is best-effort by design: subscriber channels are small and a full
// channel drops the event rather than blocking the publisher. Every agent also
// heartbeats, so a lost nudge is repaired within one interval.
type Hub struct {
	mu   sync.RWMutex
	subs map[string]map[*subscriber]struct{}
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{subs: map[string]map[*subscriber]struct{}{}}
}

// Subscribe registers a listener for one agent. The returned cancel function
// must be called exactly once when the connection ends.
func (h *Hub) Subscribe(nodeID string) (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, 8)}
	h.mu.Lock()
	if h.subs[nodeID] == nil {
		h.subs[nodeID] = map[*subscriber]struct{}{}
	}
	h.subs[nodeID][sub] = struct{}{}
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		m := h.subs[nodeID]
		if m == nil {
			return
		}
		if _, ok := m[sub]; ok {
			delete(m, sub)
			close(sub.ch)
		}
		if len(m) == 0 {
			delete(h.subs, nodeID)
		}
	}
	return sub.ch, cancel
}

// Publish sends an event to one node's subscribers.
func (h *Hub) Publish(nodeID string, ev Event) {
	if ev.At == 0 {
		ev.At = time.Now().Unix()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for sub := range h.subs[nodeID] {
		select {
		case sub.ch <- ev:
		default:
			// Subscriber is slow; it will reconcile on its next heartbeat.
		}
	}
}

// Broadcast sends an event to every connected agent.
func (h *Hub) Broadcast(ev Event) {
	if ev.At == 0 {
		ev.At = time.Now().Unix()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for nodeID, subs := range h.subs {
		ev.NodeID = nodeID
		for sub := range subs {
			select {
			case sub.ch <- ev:
			default:
			}
		}
	}
}

// Connected returns how many agents currently hold a stream, for diagnostics.
func (h *Hub) Connected() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, subs := range h.subs {
		n += len(subs)
	}
	return n
}
