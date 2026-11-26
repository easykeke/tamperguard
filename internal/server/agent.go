package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/release"
	"github.com/easykeke/tamperguard/internal/store"
	"github.com/easykeke/tamperguard/internal/token"
)

// ---------- enrolment ----------

type enrollRequest struct {
	BootstrapToken string          `json:"bootstrap_token"`
	Hostname       string          `json:"hostname"`
	Role           string          `json:"role"`
	CSRPEM         string          `json:"csr_pem"`
	AgentVersion   string          `json:"agent_version"`
	Enforcer       string          `json:"enforcer"`
	Caps           json.RawMessage `json:"caps"`
}

type enrollResponse struct {
	AgentID     string            `json:"agent_id"`
	CertPEM     string            `json:"cert_pem"`
	CAPEM       string            `json:"ca_pem"`
	ServerTime  int64             `json:"server_time"`
	AgentConfig map[string]string `json:"config"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in enrollRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Role != "protect" && in.Role != "publish" {
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	if in.Hostname == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "hostname is required")
		return
	}

	role, ok, err := s.st.ConsumeBootstrapToken(hashToken(in.BootstrapToken))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if !ok {
		// Deliberately identical to an expired token: no oracle for guessing.
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid or already used bootstrap token")
		return
	}
	if role != in.Role {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "bootstrap token is for role "+role)
		return
	}

	csr, err := parseCSR(in.CSRPEM)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	pubPEM, err := marshalEd25519Public(csr.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}

	prefix := "n_"
	if in.Role == "publish" {
		prefix = "pub_"
	}
	agentID := idgen.New(prefix)

	certPEM, err := s.signAgentCert(agentID, in.Role, csr.PublicKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	caps := in.Caps
	if len(caps) == 0 {
		caps = json.RawMessage("{}")
	}
	if err := s.st.UpsertNode(store.Node{
		ID:           agentID,
		Hostname:     in.Hostname,
		Role:         in.Role,
		Status:       "online",
		Enforcer:     in.Enforcer,
		Caps:         caps,
		AgentVersion: in.AgentVersion,
		PubKey:       pubPEM,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("agent enrolled", "agent", agentID, "role", in.Role, "host", in.Hostname)

	caPEM, err := s.caPEM()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, enrollResponse{
		AgentID:    agentID,
		CertPEM:    string(certPEM),
		CAPEM:      string(caPEM),
		ServerTime: s.now().Unix(),
		AgentConfig: map[string]string{
			"issuer_public_key":  hexKey(s.tokenPub),
			"policy_public_key":  hexKey(s.policyPub),
			"release_public_key": hexKey(s.releasePub),
			"heartbeat_seconds":  itoa(s.cfg.HeartbeatSeconds),
		},
	})
}

func (s *Server) signAgentCert(agentID, role string, pub any) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: agentID, Organization: []string{"TamperGuard " + role}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, pub, s.caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (s *Server) caPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw}), nil
}

func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR signature is invalid")
	}
	return csr, nil
}

func marshalEd25519Public(pub any) (string, error) {
	if _, ok := pub.(ed25519.PublicKey); !ok {
		return "", errors.New("agent key must be an Ed25519 key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ---------- heartbeat ----------

type heartbeatRequest struct {
	Status          string          `json:"status"`
	Enforcer        string          `json:"enforcer"`
	PolicyDigest    string          `json:"policy_digest"`
	Caps            json.RawMessage `json:"caps"`
	Degraded        bool            `json:"degraded"`
	AgentVersion    string          `json:"agent_version"`
	EnforcerHealthy bool            `json:"enforcer_healthy"`
	AuditSeq        uint64          `json:"audit_seq"`
}

type revocationView struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type heartbeatResponse struct {
	Policy            *policy.Snapshot `json:"policy"`
	Grants            []policy.Grant   `json:"grants"`
	Revocations       []revocationView `json:"revocations"`
	ServerTime        int64            `json:"server_time"`
	HeartbeatInterval int              `json:"heartbeat_interval"`
}

// bootDigestOf extracts the boot-evidence digest from the caps JSON.
func bootDigestOf(caps []byte) string {
	var v struct {
		BootDigest string `json:"boot_digest"`
	}
	if len(caps) == 0 || json.Unmarshal(caps, &v) != nil {
		return ""
	}
	return v.BootDigest
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	agentID, _ := clientCN(r)
	var in heartbeatRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if prev, err := s.st.GetNode(agentID); err == nil {
		prevDigest := bootDigestOf(prev.Caps)
		newDigest := bootDigestOf(in.Caps)
		if prevDigest != "" && newDigest != "" && prevDigest != newDigest {
			s.log.Warn("boot evidence changed", "node", agentID, "previous", prevDigest, "current", newDigest)
		}
	}
	if err := s.st.ApplyHeartbeat(store.HeartbeatInput{
		NodeID:          agentID,
		Status:          in.Status,
		Enforcer:        in.Enforcer,
		PolicyDigest:    in.PolicyDigest,
		Caps:            in.Caps,
		Degraded:        in.Degraded,
		AgentVersion:    in.AgentVersion,
		EnforcerHealthy: in.EnforcerHealthy,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	resp := heartbeatResponse{
		ServerTime:        s.now().Unix(),
		HeartbeatInterval: s.cfg.HeartbeatSeconds,
		Grants:            []policy.Grant{},
		Revocations:       []revocationView{},
	}

	if p, ok := s.policyForNode(agentID); ok {
		snap, err := policy.SignSnapshot(p, s.now().Unix(), s.policyPriv)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "policy snapshot: "+err.Error())
			return
		}
		resp.Policy = snap
		_ = s.st.SetNodePolicy(agentID, p.ID, p.Version, snap.Digest)
	}

	grants, err := s.activeGrants(agentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	resp.Grants = grants

	revs, err := s.st.ListRevocations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	now := s.now().Unix()
	for _, rv := range revs {
		resp.Revocations = append(resp.Revocations, revocationView{Kind: rv.Kind, Value: rv.Value})
	}
	_ = now
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) policyForNode(nodeID string) (policy.Policy, bool) {
	pid, err := s.st.PolicyIDForNode(nodeID)
	if err != nil {
		return policy.Policy{}, false
	}
	p, err := s.st.GetPolicy(pid)
	if err != nil {
		return policy.Policy{}, false
	}
	return p, true
}

// activeGrants converts live token records into the reduced grant form the
// enforcer understands.
func (s *Server) activeGrants(nodeID string) ([]policy.Grant, error) {
	tokens, err := s.st.ListTokens(500)
	if err != nil {
		return nil, err
	}
	now := s.now().Unix()
	revokedSubjects := map[string]bool{}
	revs, err := s.st.ListRevocations()
	if err != nil {
		return nil, err
	}
	for _, rv := range revs {
		switch rv.Kind {
		case store.RevokeSubject:
			revokedSubjects[rv.Value] = true
		}
	}
	out := []policy.Grant{}
	for _, t := range tokens {
		if t.NodeID != nodeID || t.Revoked || t.ExpiresAt <= now {
			continue
		}
		if revokedSubjects[t.Subject] {
			continue
		}
		out = append(out, policy.Grant{
			TokenID:   t.ID,
			Subject:   t.Subject,
			NodeID:    t.NodeID,
			Paths:     t.Paths,
			ExpiresAt: t.ExpiresAt,
		})
	}
	return out, nil
}

// ---------- push channel ----------

// handleStream keeps an SSE connection open and pushes change notifications
// (policy updated, revocation issued, grant issued). The events are hints: the
// agent reacts by syncing, which keeps correctness independent of delivery.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	agentID, _ := clientCN(r)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "streaming not supported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, cancel := s.hub.Subscribe(agentID)
	defer cancel()
	s.log.Info("agent stream opened", "agent", agentID, "connected", s.hub.Connected())
	defer func() {
		s.log.Info("agent stream closed", "agent", agentID)
	}()

	fmt.Fprintf(w, "event: hello\ndata: {\"node_id\":%q}\n\n", agentID)
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			payload, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, payload)
			flusher.Flush()
		case <-ping.C:
			// Comment frame keeps proxies and the kernel from idling the
			// connection out without waking the agent.
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// handleGrantReport records which release tokens the agent has actually
// installed in its enforcement map. A publisher polls this to know when the
// node is ready, instead of guessing with a fixed delay.
func (s *Server) handleGrantReport(w http.ResponseWriter, r *http.Request) {
	agentID, _ := clientCN(r)
	var in struct {
		ActiveTokens []string `json:"active_tokens"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.st.SetNodeActiveGrants(agentID, in.ActiveTokens); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(in.ActiveTokens)})
}

// handlePublishReady tells a publisher whether its token is live on the target
// node yet.
func (s *Server) handlePublishReady(w http.ResponseWriter, r *http.Request) {
	cn, _ := clientCN(r)
	reqRow, err := s.st.GetPublishRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "publish request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if reqRow.PublisherID != cn {
		writeErr(w, http.StatusForbidden, "forbidden", "request belongs to another publisher")
		return
	}
	ready := false
	if reqRow.TokenID != "" {
		ready, err = s.st.NodeHasActiveGrant(reqRow.NodeID, reqRow.TokenID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ready":    ready,
		"token_id": reqRow.TokenID,
		"node_id":  reqRow.NodeID,
		"status":   reqRow.Status,
	})
}

// ---------- audit upload ----------

type auditUploadRequest struct {
	Records []audit.Record `json:"records"`
}

func (s *Server) handleAuditUpload(w http.ResponseWriter, r *http.Request) {
	agentID, _ := clientCN(r)
	var in auditUploadRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Records) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ack_seq": 0})
		return
	}

	node, err := s.st.GetNode(agentID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "unknown agent")
		return
	}
	pub, err := parseEd25519Public(node.PubKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "agent public key unusable")
		return
	}

	row, err := s.st.GetChainState(agentID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	nextSeq := row.NextSeq
	if nextSeq == 0 {
		nextSeq = 1
	}
	cs := &audit.ChainState{AgentID: agentID, NextSeq: nextSeq, LastHash: row.LastHash}

	v := audit.NewVerifier(pub)
	for _, rec := range in.Records {
		if err := v.Next(cs, rec); err != nil {
			_ = s.st.SetChainAlert(agentID, err.Error())
			s.log.Error("audit chain broken", "agent", agentID, "seq", rec.Seq, "err", err)
			writeErr(w, http.StatusConflict, "chain_broken", err.Error())
			return
		}
	}
	if err := s.st.AppendAudit(agentID, in.Records, cs.NextSeq, cs.LastHash); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ack_seq": cs.NextSeq - 1,
		"alerts":  []string{},
	})
}

// ---------- publish agent endpoints ----------

func (s *Server) handlePublishPending(w http.ResponseWriter, r *http.Request) {
	cn, _ := clientCN(r)
	rs, err := s.st.ListPendingForPublisher(cn)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if rs == nil {
		rs = []store.PublishRequest{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (s *Server) handlePublishManifest(w http.ResponseWriter, r *http.Request) {
	cn, _ := clientCN(r)
	id := r.PathValue("id")
	reqRow, err := s.st.GetPublishRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "publish request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if reqRow.PublisherID != cn {
		writeErr(w, http.StatusForbidden, "forbidden", "request belongs to another publisher")
		return
	}
	if reqRow.Status != store.PublishPending && reqRow.Status != store.PublishManifest {
		writeErr(w, http.StatusConflict, "conflict", "request is "+reqRow.Status)
		return
	}

	var in struct {
		Manifest string `json:"manifest"`
		Files    []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"files"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Manifest == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "manifest digest is required")
		return
	}

	// Persist the manifest file list. For pull deliveries every file must have
	// been uploaded first and match the manifest exactly, so the control plane
	// never hands a node a file that differs from what the publisher hashed.
	files := make([]store.PublishFile, 0, len(in.Files))
	for _, f := range in.Files {
		rel, err := cleanRel(f.Path)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid", "file path: "+err.Error())
			return
		}
		files = append(files, store.PublishFile{Path: rel, SHA256: strings.ToLower(f.SHA256), Size: f.Size})
	}
	if err := s.st.SetPublishFiles(reqRow.ID, files); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if reqRow.Delivery == store.DeliveryPull {
		for _, f := range files {
			art, err := s.st.GetArtifact(reqRow.ID, f.Path)
			if err != nil || art.SHA256 != f.SHA256 || art.Size != f.Size {
				writeErr(w, http.StatusConflict, "conflict", "artefact missing or mismatched for "+f.Path)
				return
			}
		}
	}

	p, ok := s.policyForNode(reqRow.NodeID)
	if !ok {
		writeErr(w, http.StatusConflict, "conflict", "target node has no protection policy")
		return
	}
	paths := make([]string, 0, len(p.Paths))
	for _, pr := range p.Paths {
		paths = append(paths, pr.Path)
	}

	now := s.now()
	ttl := s.cfg.TokenTTLSeconds
	if ttl <= 0 || ttl > s.cfg.MaxTokenTTL {
		ttl = 300
	}
	claims := token.Claims{
		Version:   1,
		TokenID:   idgen.New("tok_"),
		Issuer:    "tg-server",
		Subject:   cn,
		NodeID:    reqRow.NodeID,
		Audience:  token.Audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Unix() + int64(ttl),
		Paths:     paths,
		Manifest:  in.Manifest,
	}
	raw, err := token.Sign(s.tokenPriv, claims)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "sign token: "+err.Error())
		return
	}
	if err := s.st.InsertToken(store.TokenRecord{
		ID:        claims.TokenID,
		Subject:   cn,
		NodeID:    reqRow.NodeID,
		RequestID: reqRow.ID,
		Manifest:  in.Manifest,
		Paths:     paths,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.st.UpdatePublishRequest(reqRow.ID, store.PublishToken, in.Manifest, claims.TokenID, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("release token issued", "token", claims.TokenID, "publisher", cn, "node", reqRow.NodeID)
	// Wake the target node so the grant is installed immediately instead of on
	// its next heartbeat. This is what makes publishing feel instant.
	s.hub.Publish(reqRow.NodeID, Event{Kind: EventGrant, NodeID: reqRow.NodeID})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      raw,
		"token_id":   claims.TokenID,
		"expires_at": claims.ExpiresAt,
		"paths":      paths,
	})
}

func (s *Server) handlePublishComplete(w http.ResponseWriter, r *http.Request) {
	cn, _ := clientCN(r)
	id := r.PathValue("id")
	reqRow, err := s.st.GetPublishRequest(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "publish request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if reqRow.PublisherID != cn {
		writeErr(w, http.StatusForbidden, "forbidden", "request belongs to another publisher")
		return
	}
	var in struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	status := store.PublishDone
	if !in.OK {
		status = store.PublishFailed
	}
	if err := s.st.UpdatePublishRequest(id, status, reqRow.Manifest, reqRow.TokenID, in.Error); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("publish finished", "request", id, "status", status, "publisher", cn)
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

// ---------- small helpers ----------

func hashToken(tok string) string {
	return token.DigestString(tok)
}

func hexKey(pub []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(pub)*2)
	for _, b := range pub {
		out = append(out, hexdigits[b>>4], hexdigits[b&0xf])
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// handleSiteManifest returns the signed description of the site the node should
// be serving: the latest completed pull-mode release. The web-layer proxy uses it
// instead of trusting the local disk at snapshot time.
func (s *Server) handleSiteManifest(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	req, err := s.st.LatestCompletedPublishForNode(nodeID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no_release",
			"no completed pull-mode release for this node (local-mode releases have no artefacts on the control plane)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	files, err := s.st.ListPublishFiles(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	sm := release.SiteManifest{
		NodeID:    nodeID,
		RequestID: req.ID,
		Manifest:  req.Manifest,
		TargetDir: req.TargetDir,
	}
	for _, f := range files {
		sm.Files = append(sm.Files, release.SiteFile{Path: f.Path, SHA256: f.SHA256, Size: f.Size})
	}
	if err := release.SignSiteManifest(s.policyPriv, &sm); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sm)
}
