package server

import (
	"net/http"
	"os"
	"path/filepath"
)

// handleAgentDownload serves packaged agent binaries for Linux and Windows so
// the console can offer installers and instructions without shell access.
func (s *Server) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	if file := r.URL.Query().Get("file"); file == "install-service.ps1" || file == "tg-agent-tray.ps1" || file == "verify-hardening.ps1" {
		path := filepath.Join(s.cfg.DataDir, "downloads", file)
		f, err := os.Open(path)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found", file+" not uploaded")
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
		http.ServeContent(w, r, file, info.ModTime(), f)
		return
	}
	role := r.URL.Query().Get("role")
	osName := r.URL.Query().Get("os")
	arch := r.URL.Query().Get("arch")
	if osName == "" {
		osName = "linux"
	}
	if arch == "" {
		arch = "amd64"
	}
	if osName != "linux" && osName != "windows" {
		writeErr(w, http.StatusBadRequest, "invalid", "os must be linux or windows")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		writeErr(w, http.StatusBadRequest, "invalid", "arch must be amd64 or arm64")
		return
	}
	var base string
	switch role {
	case "protect":
		base = "tg-agent"
	case "publish":
		base = "tg-publish"
	default:
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	ext := ""
	if osName == "windows" {
		ext = ".exe"
	}
	name := base + "-" + osName + "-" + arch + ext
	path := filepath.Join(s.cfg.DataDir, "downloads", name)
	f, err := os.Open(path)
	if err != nil {
		// Backwards-compatible fallback for a single-platform upload.
		path = filepath.Join(s.cfg.DataDir, "downloads", base)
		name = base + ext
		f, err = os.Open(path)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found",
				"binary not uploaded; place it under <data-dir>/downloads/"+name)
			return
		}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, info.ModTime(), f)
}
