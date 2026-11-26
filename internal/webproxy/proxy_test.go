package webproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSite(t *testing.T) (root, state string) {
	t.Helper()
	root = t.TempDir()
	state = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>trusted</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "static", "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, state
}

func TestSnapshotAndServeVerified(t *testing.T) {
	root, state := newSite(t)
	m, err := Snapshot(root, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(m.Entries))
	}
	srv, err := New(root, state, m, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 {
		t.Fatalf("GET / = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "<html>trusted</html>" {
		t.Fatalf("body = %q", got)
	}
	if got := rec.Header().Get("X-TG-Integrity"); got != "verified" {
		t.Fatalf("integrity header = %q", got)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	if rec.Code != 200 || rec.Body.String() != "console.log(1)" {
		t.Fatalf("asset = %d %q", rec.Code, rec.Body.String())
	}
}

func TestTamperedDiskServesTrustedCopy(t *testing.T) {
	root, state := newSite(t)
	m, err := Snapshot(root, state)
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := New(root, state, m, "", audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Tamper the file on disk after the snapshot.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>EVIL</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if got := rec.Body.String(); got != "<html>trusted</html>" {
		t.Fatalf("served %q, want the trusted copy", got)
	}
	if got := rec.Header().Get("X-TG-Integrity"); got != "restored" {
		t.Fatalf("integrity header = %q, want restored", got)
	}
	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "web.tamper-detected") || !strings.Contains(string(raw), `"/index.html"`) {
		t.Fatalf("audit trail missing the tamper event: %s", raw)
	}
}

func TestUnknownPath(t *testing.T) {
	root, state := newSite(t)
	m, err := Snapshot(root, state)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(root, state, m, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attacker.html", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", rec.Code)
	}

	// With an upstream, unknown paths are forwarded so dynamic apps keep working.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "1")
		_, _ = io.WriteString(w, "dynamic:"+r.URL.Path)
	}))
	defer upstream.Close()
	srv2, err := New(root, state, m, upstream.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	rec = httptest.NewRecorder()
	srv2.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/users", nil))
	if rec.Code != 200 || rec.Header().Get("X-Upstream") != "1" || rec.Body.String() != "dynamic:/app/users" {
		t.Fatalf("upstream passthrough = %d %q", rec.Code, rec.Body.String())
	}
}

func TestCleanRequestPath(t *testing.T) {
	cases := map[string]string{
		"/":              "index.html",
		"/index.html":    "index.html",
		"/static/app.js": "static/app.js",
		"/dir/":          "dir/",
	}
	for in, want := range cases {
		got, err := CleanRequestPath(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
	if _, err := CleanRequestPath("/../etc/passwd"); err == nil {
		t.Fatal("traversal path accepted")
	}
	if _, err := CleanRequestPath(`\windows\system32`); err == nil {
		t.Fatal("backslash path accepted")
	}
}

func TestSnapshotRejectsSymlink(t *testing.T) {
	root, state := newSite(t)
	if err := os.Symlink(filepath.Join(root, "index.html"), filepath.Join(root, "link.html")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := Snapshot(root, state); err == nil {
		t.Fatal("snapshot followed a symlink")
	}
}
