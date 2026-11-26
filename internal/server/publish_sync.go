package server

import (
	"net/http"

	"github.com/easykeke/tamperguard/internal/store"
)

// handlePublisherSync lets a publish agent create its own release request. This
// is the "manual trigger from the publisher host" path: an operator runs
// `tg-publish sync ...` instead of an administrator creating a request in the
// console. The publisher identity is taken from the mTLS certificate, so it can
// only create requests for itself.
func (s *Server) handlePublisherSync(w http.ResponseWriter, r *http.Request) {
	publisherID, _ := clientCN(r)
	var in struct {
		NodeID    string `json:"node_id"`
		SourceDir string `json:"source_dir"`
		TargetDir string `json:"target_dir"`
		Note      string `json:"note"`
		Mode      string `json:"mode"`
		Delivery  string `json:"delivery"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.SourceDir == "" || in.TargetDir == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "source_dir and target_dir are required")
		return
	}
	if in.Mode == "" {
		in.Mode = store.ModeFull
	}
	if in.Mode != store.ModeFull && in.Mode != store.ModeIncremental {
		writeErr(w, http.StatusBadRequest, "invalid", "mode must be full or incremental")
		return
	}
	if in.Delivery == "" {
		in.Delivery = store.DeliveryPull
	}
	if in.Delivery != store.DeliveryLocal && in.Delivery != store.DeliveryPull {
		writeErr(w, http.StatusBadRequest, "invalid", "delivery must be local or pull")
		return
	}
	node, err := s.st.GetNode(in.NodeID)
	if err != nil || node.Role != "protect" || node.Revoked {
		writeErr(w, http.StatusBadRequest, "invalid", "node_id must reference a live protect node")
		return
	}
	req, err := s.st.CreatePublishRequest(store.PublishRequest{
		NodeID:      in.NodeID,
		PublisherID: publisherID,
		SourceDir:   in.SourceDir,
		TargetDir:   in.TargetDir,
		Note:        in.Note,
		Mode:        in.Mode,
		Delivery:    in.Delivery,
		CreatedBy:   "publisher:" + publisherID,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("publisher-triggered sync created", "request", req.ID, "node", req.NodeID,
		"publisher", publisherID, "mode", req.Mode)
	writeJSON(w, http.StatusCreated, req)
}

// handlePublisherNodes lists protect nodes for the publisher's interactive
// setup wizard, so a beginner never has to copy a node id by hand.
func (s *Server) handlePublisherNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.st.ListNodes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]map[string]string, 0, len(nodes))
	for _, n := range nodes {
		if n.Role != "protect" || n.Revoked {
			continue
		}
		out = append(out, map[string]string{
			"id":       n.ID,
			"hostname": n.Hostname,
			"status":   n.Status,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePublisherCurrent returns the last completed release for a node so an
// incremental publisher can compare hashes without reading the target host.
func (s *Server) handlePublisherCurrent(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "node_id is required")
		return
	}
	if node, err := s.st.GetNode(nodeID); err != nil || node.Role != "protect" {
		writeErr(w, http.StatusBadRequest, "invalid", "node_id must reference a protect node")
		return
	}
	req, err := s.st.LatestCompletedReleaseForNode(nodeID)
	if err != nil {
		// No baseline yet: the publisher treats every file as changed.
		writeJSON(w, http.StatusOK, map[string]any{"files": []store.PublishFile{}, "mode": store.ModeFull})
		return
	}
	files, err := s.st.ListPublishFiles(req.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if files == nil {
		files = []store.PublishFile{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": req.ID,
		"mode":       req.Mode,
		"target_dir": req.TargetDir,
		"manifest":   req.Manifest,
		"files":      files,
	})
}
