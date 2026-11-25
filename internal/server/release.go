package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/easykeke/tamperguard/internal/release"
	"github.com/easykeke/tamperguard/internal/store"
)

// releaseFilePath is where published agent binaries live:
// <data-dir>/releases/<version>/tg-agent-<os>-<arch>
func (s *Server) releaseFilePath(version, osName, arch string) string {
	return filepath.Join(s.cfg.DataDir, "releases", version, "tg-agent-"+osName+"-"+arch)
}

// handleUpgrade tells an agent whether a newer signed build exists.
func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	osName, arch := q.Get("os"), q.Get("arch")
	current := q.Get("current")
	if osName == "" || arch == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "os and arch are required")
		return
	}
	rel, err := s.st.LatestRelease(osName, arch)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "current": current})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	m := release.Manifest{
		Version: rel.Version,
		OS:      rel.OS,
		Arch:    rel.Arch,
		SHA256:  rel.SHA256,
		Size:    rel.Size,
	}
	if err := m.Sign(s.releasePriv); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "sign manifest: "+err.Error())
		return
	}
	available := rel.Version != current
	s.log.Info("agent upgrade check", "current", current, "available", rel.Version, "offered", available)
	writeJSON(w, http.StatusOK, map[string]any{
		"available": available,
		"current":   current,
		"manifest":  m,
	})
}

// handleUpgradeDownload streams the published binary.
func (s *Server) handleUpgradeDownload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	version, osName, arch := q.Get("version"), q.Get("os"), q.Get("arch")
	if version == "" || osName == "" || arch == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "version, os and arch are required")
		return
	}
	// Only versions that exist in the database are served, which also keeps the
	// path built below free of traversal.
	if _, err := s.st.GetRelease(version, osName, arch); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "release not found")
		return
	}
	path := s.releaseFilePath(version, osName, arch)
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "release artefact missing")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.Header().Set("Content-Disposition", `attachment; filename="tg-agent"`)
	http.ServeContent(w, r, "tg-agent", st.ModTime(), f)
}
