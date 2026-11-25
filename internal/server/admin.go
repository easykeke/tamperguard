package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/store"
)

// ---------- overview ----------

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.st.Overview(int64(3 * s.cfg.HeartbeatSeconds))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

// ---------- nodes ----------

func (s *Server) decorateNode(n store.Node) store.Node {
	if n.Role == "" {
		n.Role = "protect"
	}
	window := int64(3 * s.cfg.HeartbeatSeconds)
	if n.Role == "protect" && s.now().Unix()-n.LastSeen > window {
		n.Status = "offline"
	}
	if n.Status == "" {
		n.Status = "offline"
	}
	return n
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.st.ListNodes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]store.Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.decorateNode(n))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.st.GetNode(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	recs, err := s.st.ListAudit(store.AuditFilter{NodeID: id, Limit: 20})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node":         s.decorateNode(n),
		"recent_audit": recs,
	})
}

func (s *Server) handleDegradedApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Approved bool `json:"approved"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	n, err := s.st.GetNode(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !n.Degraded && body.Approved {
		writeErr(w, http.StatusConflict, "conflict", "node is not in degraded mode; nothing to approve")
		return
	}
	if err := s.st.ApproveDegraded(id, body.Approved); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Warn("degraded approval changed", "node", id, "approved", body.Approved, "remote", r.RemoteAddr)
	n, _ = s.st.GetNode(id)
	writeJSON(w, http.StatusOK, s.decorateNode(n))
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.st.SetNodeRevoked(id, true); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.st.AddRevocation(store.RevokeNode, id, "node revoked by administrator"); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Warn("node identity revoked", "node", id, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ---------- policies ----------

type policyInput struct {
	Name        string              `json:"name"`
	Paths       []policy.PathRule   `json:"paths"`
	Writers     []policy.WriterRule `json:"writers"`
	AssignNodes []string            `json:"assign_nodes"`
}

func (in policyInput) toPolicy(id string) policy.Policy {
	return policy.Policy{ID: id, Name: in.Name, Paths: in.Paths, Writers: in.Writers}
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.st.ListPolicies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if ps == nil {
		ps = []policy.Policy{}
	}
	writeJSON(w, http.StatusOK, ps)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	p := in.toPolicy("")
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	created, err := s.st.CreatePolicy(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, nodeID := range in.AssignNodes {
		if _, err := s.st.GetNode(nodeID); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid", "unknown node "+nodeID)
			return
		}
		if err := s.st.AssignPolicy(nodeID, created.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	s.log.Info("policy created", "policy", created.ID, "name", created.Name)
	s.hub.Broadcast(Event{Kind: EventPolicy})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.GetPolicy(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	p := in.toPolicy(r.PathValue("id"))
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	updated, err := s.st.UpdatePolicy(p)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, nodeID := range in.AssignNodes {
		if err := s.st.AssignPolicy(nodeID, updated.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	s.log.Info("policy updated", "policy", updated.ID, "version", updated.Version)
	s.hub.Broadcast(Event{Kind: EventPolicy})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	err := s.st.DeletePolicy(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------- publish requests ----------

func (s *Server) handleListPublish(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	limit := int(parseUint(r.URL.Query().Get("limit"), 100))
	rs, err := s.st.ListPublishRequests(status, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if rs == nil {
		rs = []store.PublishRequest{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (s *Server) handleCreatePublish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		NodeID      string `json:"node_id"`
		PublisherID string `json:"publisher_id"`
		SourceDir   string `json:"source_dir"`
		TargetDir   string `json:"target_dir"`
		Note        string `json:"note"`
		Delivery    string `json:"delivery"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Delivery == "" {
		in.Delivery = store.DeliveryLocal
	}
	if in.Delivery != store.DeliveryLocal && in.Delivery != store.DeliveryPull {
		writeErr(w, http.StatusBadRequest, "invalid", "delivery must be local or pull")
		return
	}
	node, err := s.st.GetNode(in.NodeID)
	if err != nil || node.Role != "protect" {
		writeErr(w, http.StatusBadRequest, "invalid", "node_id must reference a protect node")
		return
	}
	pub, err := s.st.GetNode(in.PublisherID)
	if err != nil || pub.Role != "publish" {
		writeErr(w, http.StatusBadRequest, "invalid", "publisher_id must reference a publish agent")
		return
	}
	if pub.Revoked || node.Revoked {
		writeErr(w, http.StatusConflict, "revoked", "node or publisher identity is revoked")
		return
	}
	user, _ := s.sessionUser(r)
	req, err := s.st.CreatePublishRequest(store.PublishRequest{
		NodeID:      in.NodeID,
		PublisherID: in.PublisherID,
		SourceDir:   in.SourceDir,
		TargetDir:   in.TargetDir,
		Note:        in.Note,
		Delivery:    in.Delivery,
		CreatedBy:   user,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("publish request created", "request", req.ID, "node", req.NodeID, "publisher", req.PublisherID)
	writeJSON(w, http.StatusCreated, req)
}

func (s *Server) handleGetPublish(w http.ResponseWriter, r *http.Request) {
	req, err := s.st.GetPublishRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "publish request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleCancelPublish(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, err := s.st.GetPublishRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "publish request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	switch req.Status {
	case store.PublishPending, store.PublishManifest:
	default:
		writeErr(w, http.StatusConflict, "conflict", "request already "+req.Status)
		return
	}
	if err := s.st.UpdatePublishRequest(id, store.PublishCancelled, req.Manifest, req.TokenID, "cancelled by administrator"); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": store.PublishCancelled})
}

// ---------- tokens and revocations ----------

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.st.ListTokens(int(parseUint(r.URL.Query().Get("limit"), 100)))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if ts == nil {
		ts = []store.TokenRecord{}
	}
	writeJSON(w, http.StatusOK, ts)
}

func (s *Server) handleListRevocations(w http.ResponseWriter, r *http.Request) {
	rs, err := s.st.ListRevocations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if rs == nil {
		rs = []store.Revocation{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (s *Server) handleCreateRevocation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind   string `json:"kind"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Value == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "value is required")
		return
	}
	switch in.Kind {
	case store.RevokeToken:
		if err := s.st.MarkTokenRevoked(in.Value); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	case store.RevokeNode:
		if err := s.st.SetNodeRevoked(in.Value, true); errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "node not found")
			return
		} else if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	case store.RevokeSubject:
		// A subject revocation only needs the list entry; agents refuse any
		// grant whose subject appears here.
	default:
		writeErr(w, http.StatusBadRequest, "invalid", "kind must be token, subject or node")
		return
	}
	if err := s.st.AddRevocation(in.Kind, in.Value, in.Reason); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Warn("revocation issued", "kind", in.Kind, "value", in.Value, "remote", r.RemoteAddr)
	// Push immediately; the polling heartbeat is the fallback.
	s.hub.Broadcast(Event{Kind: EventRevoke})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "revoked"})
}

// ---------- audit ----------

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{
		NodeID:    q.Get("node_id"),
		Kind:      q.Get("kind"),
		Limit:     int(parseUint(q.Get("limit"), 200)),
		BeforeSeq: int64(parseUint(q.Get("before_seq"), 0)),
	}
	recs, err := s.st.ListAudit(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

// handleAuditExport streams audit records as JSON Lines or CSV for compliance
// evidence collection.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "csv" {
		writeErr(w, http.StatusBadRequest, "invalid", "format must be jsonl or csv")
		return
	}
	recs, err := s.st.ListAudit(store.AuditFilter{
		NodeID: q.Get("node_id"),
		Kind:   q.Get("kind"),
		Limit:  int(parseUint(q.Get("limit"), 100000)),
		From:   int64(parseUint(q.Get("from"), 0)),
		To:     int64(parseUint(q.Get("to"), 0)),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	filename := fmt.Sprintf("tamperguard-audit-%s.%s", time.Now().UTC().Format("20060102-150405"), format)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		enc := json.NewEncoder(w)
		for _, rec := range recs {
			if err := enc.Encode(rec); err != nil {
				return
			}
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"seq", "time_utc", "agent", "kind", "decision", "path", "op", "subject", "token_id", "detail", "hash", "prev_hash"})
	for _, rec := range recs {
		_ = cw.Write([]string{
			strconv.FormatUint(rec.Seq, 10),
			time.Unix(rec.Time, 0).UTC().Format(time.RFC3339),
			rec.AgentID, rec.Kind, rec.Decision, rec.Path, rec.Op,
			rec.Subject, rec.TokenID, rec.Detail, rec.Hash, rec.PrevHash,
		})
	}
	cw.Flush()
}

func (s *Server) handleAuditState(w http.ResponseWriter, r *http.Request) {
	states, err := s.st.ListChainStates()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if states == nil {
		states = []store.ChainStateRow{}
	}
	writeJSON(w, http.StatusOK, states)
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("node_id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "node_id is required")
		return
	}
	node, err := s.st.GetNode(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	pub, err := parseEd25519Public(node.PubKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "agent public key unusable: "+err.Error())
		return
	}
	recs, err := s.st.AuditForAgent(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	v := audit.NewVerifier(pub)
	fromSeq, err := v.VerifyRange(recs)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "records": len(recs), "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "records": len(recs), "from_seq": fromSeq,
		"note": "verification starts at the oldest stored record; earlier records may have been purged by retention",
	})
}

// ---------- helpers ----------

func parseEd25519Public(pemText string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", k)
	}
	return pub, nil
}
