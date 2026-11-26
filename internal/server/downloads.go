package server

import (
	"net/http"
	"os"
	"path/filepath"
)

// handleAgentDownload serves the packaged agent binaries so the console can
// offer protected-endpoint / publisher installers without shell access.
func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	var name string
	switch role {
	case "protect":
		name = "tg-agent"
	case "publish":
		name = "tg-publish"
	default:
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	path := filepath.Join(s.cfg.DataDir, "downloads", name)
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found",
			"agent binary not uploaded to the control plane; place it under <data-dir>/downloads/"+name)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-linux-amd64"`)
	http.ServeContent(w, r, name, info.ModTime(), f)
}
