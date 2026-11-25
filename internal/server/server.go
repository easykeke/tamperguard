// Package server is the TamperGuard control plane HTTP service.
//
// One listener serves both planes:
//   - /api/v1/* admin calls authenticated by a signed session cookie;
//   - /api/v1/agent/* and /api/v1/publish/* machine calls authenticated by
//     mutual TLS against the TamperGuard CA, with the client certificate CN
//     carrying the agent identity.
package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/store"
)

// Version is reported by /healthz and by agents on enrollment.
const Version = "0.1.0"

// Options tune optional behaviour.
type Options struct {
	UI     fs.FS
	Logger *slog.Logger
	Now    func() time.Time
}

// Server holds all control-plane state.
type Server struct {
	cfg *config.Server
	st  *store.Store
	log *slog.Logger
	now func() time.Time

	tokenPub    ed25519.PublicKey
	tokenPriv   ed25519.PrivateKey
	policyPub   ed25519.PublicKey
	policyPriv  ed25519.PrivateKey
	releasePub  ed25519.PublicKey
	releasePriv ed25519.PrivateKey
	caCert      *x509.Certificate
	caKey       crypto.Signer
	sessionKey  []byte
	tlsConf     *tls.Config

	mux *http.ServeMux
	ui  fs.FS
	hub *Hub

	stop     chan struct{}
	stopOnce sync.Once
}

// New loads keys and builds the server. It fails closed: if any key material
// is missing or malformed the control plane does not start.
func New(cfg *config.Server, st *store.Store, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{cfg: cfg, st: st, log: opts.Logger, now: opts.Now, ui: opts.UI, hub: NewHub(),
		stop: make(chan struct{})}

	var err error
	if s.sessionKey, err = cfg.SessionKeyBytes(); err != nil {
		return nil, err
	}
	if s.tokenPriv, err = config.ReadEd25519Private(cfg.KeyPath(config.TokenSignFile)); err != nil {
		return nil, fmt.Errorf("server: token signing key: %w", err)
	}
	s.tokenPub = s.tokenPriv.Public().(ed25519.PublicKey)
	if s.policyPriv, err = config.ReadEd25519Private(cfg.KeyPath(config.PolicySignFile)); err != nil {
		return nil, fmt.Errorf("server: policy signing key: %w", err)
	}
	s.policyPub = s.policyPriv.Public().(ed25519.PublicKey)

	if s.releasePriv, err = config.ReadEd25519Private(cfg.KeyPath(config.ReleaseSignFile)); err != nil {
		return nil, fmt.Errorf("server: release signing key: %w", err)
	}
	s.releasePub = s.releasePriv.Public().(ed25519.PublicKey)

	if s.caCert, s.caKey, err = loadCA(cfg.KeyPath(config.CACertFile), cfg.KeyPath(config.CAKeyFile)); err != nil {
		return nil, err
	}
	if s.tlsConf, err = buildTLSConfig(cfg, s.caCert); err != nil {
		return nil, err
	}

	s.routes()
	if cfg.AuditRetentionDays > 0 {
		go s.retentionLoop()
	}
	return s, nil
}

// retentionLoop enforces the optional audit retention window. Records are
// evidence, so retention is off unless the operator sets it explicitly.
func (s *Server) retentionLoop() {
	purge := func() {
		cutoff := s.now().Add(-time.Duration(s.cfg.AuditRetentionDays) * 24 * time.Hour).Unix()
		n, err := s.st.PurgeAuditBefore(cutoff)
		if err != nil {
			s.log.Warn("audit retention purge failed", "err", err)
			return
		}
		if n > 0 {
			s.log.Info("audit retention purged records", "count", n, "retention_days", s.cfg.AuditRetentionDays)
		}
	}
	purge()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			purge()
		}
	}
}

func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("server: read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("server: CA cert is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("server: parse CA cert: %w", err)
	}
	key, err := config.ReadPrivateKey(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("server: read CA key: %w", err)
	}
	return cert, key, nil
}

func buildTLSConfig(cfg *config.Server, ca *x509.Certificate) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.KeyPath(config.ServerCertFile), cfg.KeyPath(config.ServerKeyFile))
	if err != nil {
		return nil, fmt.Errorf("server: load TLS keypair: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Agents must present a certificate issued by our CA; enrolment is the
		// one endpoint reachable without one, and it is gated by a one-time
		// bootstrap token instead.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS13,
	}, nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	s.mux = m

	m.HandleFunc("GET /healthz", s.handleHealth)

	m.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	m.Handle("POST /api/v1/auth/logout", s.admin(s.handleLogout))
	m.Handle("GET /api/v1/auth/me", s.admin(s.handleMe))

	m.HandleFunc("POST /api/v1/agent/enroll", s.handleEnroll)
	m.Handle("POST /api/v1/agent/heartbeat", s.agent("protect", s.handleHeartbeat))
	m.Handle("POST /api/v1/agent/audit", s.agent("protect", s.handleAuditUpload))
	m.Handle("POST /api/v1/agent/grants", s.agent("protect", s.handleGrantReport))
	m.Handle("GET /api/v1/agent/upgrade", s.agent("protect", s.handleUpgrade))
	m.Handle("GET /api/v1/agent/upgrade/download", s.agent("protect", s.handleUpgradeDownload))
	m.Handle("GET /api/v1/agent/stream", s.agent("protect", s.handleStream))

	m.Handle("GET /api/v1/overview", s.admin(s.handleOverview))

	m.Handle("GET /api/v1/nodes", s.admin(s.handleListNodes))
	m.Handle("GET /api/v1/nodes/{id}", s.admin(s.handleGetNode))
	m.Handle("POST /api/v1/nodes/{id}/degraded-approval", s.admin(s.handleDegradedApproval))
	m.Handle("DELETE /api/v1/nodes/{id}", s.admin(s.handleRevokeNode))

	m.Handle("GET /api/v1/policies", s.admin(s.handleListPolicies))
	m.Handle("POST /api/v1/policies", s.admin(s.handleCreatePolicy))
	m.Handle("GET /api/v1/policies/{id}", s.admin(s.handleGetPolicy))
	m.Handle("PUT /api/v1/policies/{id}", s.admin(s.handleUpdatePolicy))
	m.Handle("DELETE /api/v1/policies/{id}", s.admin(s.handleDeletePolicy))

	m.Handle("GET /api/v1/publish-requests", s.admin(s.handleListPublish))
	m.Handle("POST /api/v1/publish-requests", s.admin(s.handleCreatePublish))
	m.Handle("GET /api/v1/publish-requests/{id}", s.admin(s.handleGetPublish))
	m.Handle("POST /api/v1/publish-requests/{id}/cancel", s.admin(s.handleCancelPublish))

	m.Handle("GET /api/v1/tokens", s.admin(s.handleListTokens))
	m.Handle("GET /api/v1/revocations", s.admin(s.handleListRevocations))
	m.Handle("POST /api/v1/revocations", s.admin(s.handleCreateRevocation))

	m.Handle("GET /api/v1/audit", s.admin(s.handleListAudit))
	m.Handle("GET /api/v1/audit/export", s.admin(s.handleAuditExport))
	m.Handle("GET /api/v1/audit/state", s.admin(s.handleAuditState))
	m.Handle("GET /api/v1/audit/verify", s.admin(s.handleAuditVerify))

	m.Handle("GET /api/v1/publish/pending", s.agent("publish", s.handlePublishPending))
	m.Handle("POST /api/v1/publish/{id}/artifact", s.agent("publish", s.handlePublishArtifact))
	m.Handle("POST /api/v1/publish/{id}/manifest", s.agent("publish", s.handlePublishManifest))
	m.Handle("POST /api/v1/publish/{id}/complete", s.agent("publish", s.handlePublishComplete))
	m.Handle("GET /api/v1/publish/{id}/ready", s.agent("publish", s.handlePublishReady))

	m.Handle("GET /api/v1/agent/deliveries", s.agent("protect", s.handleDeliveries))
	m.Handle("GET /api/v1/agent/deliveries/{id}", s.agent("protect", s.handleDeliveryInfo))
	m.Handle("GET /api/v1/agent/deliveries/{id}/artifact", s.agent("protect", s.handleDeliveryArtifact))
	m.Handle("POST /api/v1/agent/deliveries/{id}/complete", s.agent("protect", s.handleDeliveryComplete))

	m.HandleFunc("GET /", s.handleUI)
}

// Handler returns the middleware-wrapped root handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		s.mux.ServeHTTP(w, r)
	})
}

// Serve runs the control plane until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		TLSConfig:         s.tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		<-ctx.Done()
		s.stopOnce.Do(func() { close(s.stop) })
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.log.Info("control plane listening", "addr", s.cfg.ListenAddr, "version", Version)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ---------- middleware ----------

func (s *Server) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionUser(r); !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		// Requiring JSON on mutating calls blocks classic form-based CSRF: a
		// cross-site form cannot set this content type without a preflight.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeErr(w, http.StatusUnsupportedMediaType, "invalid", "Content-Type must be application/json")
				return
			}
		}
		next(w, r)
	})
}

func (s *Server) agent(role string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := clientCN(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "client certificate required")
			return
		}
		node, err := s.st.GetNode(id)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "unknown agent identity")
			return
		}
		if node.Revoked {
			writeErr(w, http.StatusForbidden, "revoked", "agent identity revoked")
			return
		}
		if node.Role != role {
			writeErr(w, http.StatusForbidden, "forbidden", "wrong agent role for this endpoint")
			return
		}
		next(w, r)
	})
}

// ---------- helpers ----------

func clientCN(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return "", false
	}
	return cn, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// decodeJSON reads a bounded JSON body. It returns false after writing the
// error response.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "request body too large or unreadable")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "malformed JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": Version, "time": s.now().Unix()})
}

// handleUI serves the embedded admin console. Unknown paths fall back to
// index.html so client-side routing works on refresh.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.ui == nil {
		writeErr(w, http.StatusNotFound, "not_found", "admin UI not bundled in this build")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	if _, err := fs.Stat(s.ui, name); err != nil {
		name = "index.html"
	}
	data, err := fs.ReadFile(s.ui, name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "asset not found")
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}
