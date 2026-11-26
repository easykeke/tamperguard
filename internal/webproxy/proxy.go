package webproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is one line of the proxy audit trail.
type AuditEvent struct {
	Time     int64  `json:"time"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Expected string `json:"expected,omitempty"`
	Got      string `json:"got,omitempty"`
	Action   string `json:"action,omitempty"`
	Remote   string `json:"remote,omitempty"`
}

// Server is the verifying static content server.
type Server struct {
	Root     string
	State    string
	Manifest *Manifest
	Upstream *url.URL
	Logger   *slog.Logger

	auditMu sync.Mutex
	audit   *os.File

	proxy *httputil.ReverseProxy
}

// New builds a server. auditPath may be empty to disable the audit trail.
func New(root, state string, m *Manifest, upstream string, auditPath string, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{Root: root, State: state, Manifest: m, Logger: logger}
	if upstream != "" {
		u, err := url.Parse(upstream)
		if err != nil {
			return nil, err
		}
		s.Upstream = u
		s.proxy = httputil.NewSingleHostReverseProxy(u)
	}
	if auditPath != "" {
		if err := os.MkdirAll(filepath.Dir(auditPath), 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		s.audit = f
	}
	return s, nil
}

// Close releases the audit file.
func (s *Server) Close() error {
	if s.audit != nil {
		return s.audit.Close()
	}
	return nil
}

// ServeHTTP serves manifest entries only. Unknown paths are forwarded to the
// upstream (when configured) so dynamic applications keep working; without an
// upstream they are 404, which also hides files an attacker added to the root.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if s.proxy != nil {
			s.proxy.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel, err := CleanRequestPath(r.URL.Path)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entry, ok := s.Manifest.Lookup(rel)
	if !ok {
		if s.proxy != nil {
			s.proxy.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	data, integrity := s.resolve(rel, entry)
	if data == nil {
		s.Logger.Error("webproxy: neither the disk file nor the trusted blob is readable", "path", rel)
		http.Error(w, "integrity source unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-TG-Integrity", integrity)
	w.Header().Set("ETag", `"`+entry.SHA256[:32]+`"`)
	w.Header().Set("Cache-Control", "no-cache")
	mod := time.Unix(entry.ModAt, 0)
	http.ServeContent(w, r, rel, mod, bytes.NewReader(data))
}

// resolve returns the content to serve: the disk file when its hash matches the
// manifest, otherwise the trusted blob (with an audit record).
func (s *Server) resolve(rel string, entry Entry) ([]byte, string) {
	diskPath := filepath.Join(s.Root, filepath.FromSlash(rel))
	if data, err := os.ReadFile(diskPath); err == nil {
		if sha256Hex(data) == entry.SHA256 {
			return data, "verified"
		}
		got := sha256Hex(data)
		s.auditEvent(AuditEvent{
			Time: time.Now().Unix(), Kind: "web.tamper-detected", Path: "/" + rel,
			Expected: entry.SHA256, Got: got, Action: "served-baseline",
		})
		s.Logger.Warn("webproxy: disk content diverges from the manifest, serving the trusted copy",
			"path", "/"+rel, "expected", entry.SHA256[:12], "got", got[:12])
	} else if !os.IsNotExist(err) {
		s.Logger.Warn("webproxy: cannot read the disk file", "path", diskPath, "err", err)
	}
	blob, err := os.ReadFile(filepath.Join(BlobDir(s.State), entry.SHA256))
	if err != nil {
		return nil, ""
	}
	if sha256Hex(blob) != entry.SHA256 {
		s.Logger.Error("webproxy: trusted blob is corrupted", "sha", entry.SHA256)
		return nil, ""
	}
	return blob, "restored"
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Server) auditEvent(ev AuditEvent) {
	if s.audit == nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	enc, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = s.audit.Write(append(enc, '\n'))
	_ = s.audit.Sync()
}

// Healthz reports readiness and the manifest size.
func (s *Server) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"files":   len(s.Manifest.Entries),
		"created": s.Manifest.CreatedAt,
		"upstream": func() string {
			if s.Upstream == nil {
				return ""
			}
			return s.Upstream.String()
		}(),
	})
}

// Handler returns the mux (health + static).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.Healthz)
	mux.Handle("/", s)
	return mux
}
