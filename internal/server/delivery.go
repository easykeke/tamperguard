package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/easykeke/tamperguard/internal/store"
)

// maxArtifactSize bounds one uploaded file.
const maxArtifactSize = 1 << 30 // 1 GiB

// artifactRoot is where pull-mode artefacts are staged:
// <data-dir>/artifacts/<request-id>/<sha256(relpath)>
func (s *Server) artifactRoot(requestID string) string {
	return filepath.Join(s.cfg.DataDir, "artifacts", requestID)
}

// cleanRel rejects absolute paths, traversal and empty components.
func cleanRel(p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return "", errors.New("path must be a clean relative path")
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path must be a clean relative path")
	}
	return cleaned, nil
}

func artifactName(rel string) string {
	sum := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(sum[:])
}

// handlePublishArtifact accepts one file of a pull-mode release.
func (s *Server) handlePublishArtifact(w http.ResponseWriter, r *http.Request) {
	cn, _ := clientCN(r)
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
	if req.PublisherID != cn {
		writeErr(w, http.StatusForbidden, "forbidden", "request belongs to another publisher")
		return
	}
	if req.Delivery != store.DeliveryPull {
		writeErr(w, http.StatusConflict, "conflict", "request is not in pull delivery mode")
		return
	}
	if req.Status != store.PublishPending && req.Status != store.PublishManifest {
		writeErr(w, http.StatusConflict, "conflict", "request is "+req.Status)
		return
	}
	rel, err := cleanRel(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	want := strings.ToLower(strings.TrimSpace(r.Header.Get("X-TG-SHA256")))
	if len(want) != 64 {
		writeErr(w, http.StatusBadRequest, "invalid", "X-TG-SHA256 header is required")
		return
	}

	dir := s.artifactRoot(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r.Body, maxArtifactSize+1))
	if cerr := tmp.Sync(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if n > maxArtifactSize {
		writeErr(w, http.StatusRequestEntityTooLarge, "invalid", "artefact exceeds size limit")
		return
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		writeErr(w, http.StatusBadRequest, "invalid", "artefact hash mismatch")
		return
	}
	final := filepath.Join(dir, artifactName(rel))
	if err := os.Rename(name, final); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.st.RecordArtifact(id, store.Artifact{Path: rel, SHA256: got, Size: n}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": rel, "sha256": got, "size": n})
}

// handleDeliveries lists pull-mode releases waiting for this node.
func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	rs, err := s.st.ListPullDeliveriesForNode(nodeID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if rs == nil {
		rs = []store.PublishRequest{}
	}
	writeJSON(w, http.StatusOK, rs)
}

// handleDeliveryInfo returns the manifest and file hashes for one delivery.
func (s *Server) handleDeliveryInfo(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	req, err := s.st.GetPublishRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "delivery not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.NodeID != nodeID || req.Delivery != store.DeliveryPull {
		writeErr(w, http.StatusForbidden, "forbidden", "delivery does not belong to this node")
		return
	}
	if req.Status != store.PublishToken && req.Status != store.PublishDelivering {
		writeErr(w, http.StatusConflict, "conflict", "delivery is "+req.Status)
		return
	}
	files, err := s.st.ListPublishFiles(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request":    req,
		"files":      files,
		"manifest":   req.Manifest,
		"target_dir": req.TargetDir,
	})
}

// handleDeliveryArtifact streams one staged file to the target node.
func (s *Server) handleDeliveryArtifact(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	id := r.PathValue("id")
	req, err := s.st.GetPublishRequest(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "delivery not found")
		return
	}
	if req.NodeID != nodeID || req.Delivery != store.DeliveryPull {
		writeErr(w, http.StatusForbidden, "forbidden", "delivery does not belong to this node")
		return
	}
	rel, err := cleanRel(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	art, err := s.st.GetArtifact(id, rel)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "artefact not uploaded")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	f, err := os.Open(filepath.Join(s.artifactRoot(id), artifactName(rel)))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "artefact file missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-TG-SHA256", art.SHA256)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", art.Size))
	http.ServeContent(w, r, "artifact", time.Time{}, f)
}

// handleDeliveryComplete closes a pull delivery.
func (s *Server) handleDeliveryComplete(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	id := r.PathValue("id")
	req, err := s.st.GetPublishRequest(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "delivery not found")
		return
	}
	if req.NodeID != nodeID {
		writeErr(w, http.StatusForbidden, "forbidden", "delivery does not belong to this node")
		return
	}
	var in struct {
		OK            bool   `json:"ok"`
		Error         string `json:"error"`
		VerifyDigest  string `json:"verify_digest"`
		VerifiedFiles int    `json:"verified_files"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	status := store.PublishDone
	if !in.OK {
		status = store.PublishFailed
	}
	if in.VerifyDigest != "" {
		_ = s.st.SetPublishVerification(id, in.VerifyDigest, in.VerifiedFiles)
	}
	if err := s.st.UpdatePublishRequest(id, status, req.Manifest, req.TokenID, in.Error); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.ProfileID != "" {
		_ = s.st.UpdateSyncProfileRun(req.ProfileID, status)
	}
	s.log.Info("pull delivery finished", "request", id, "status", status, "node", nodeID)
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}
