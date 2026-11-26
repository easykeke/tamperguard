package server

import (
	"errors"
	"net/http"

	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/store"
)

// ---------- console-managed sync profiles ----------

func (s *Server) validateSyncProfile(in *store.SyncProfile) string {
	if in.PublisherID == "" || in.NodeID == "" || in.SourceDir == "" || in.TargetDir == "" {
		return "publisher_id, node_id, source_dir and target_dir are required"
	}
	if in.Mode == "" {
		in.Mode = store.ModeFull
	}
	if in.Mode != store.ModeFull && in.Mode != store.ModeIncremental {
		return "mode must be full or incremental"
	}
	if in.Delivery == "" {
		in.Delivery = store.DeliveryPull
	}
	if in.Delivery != store.DeliveryLocal && in.Delivery != store.DeliveryPull {
		return "delivery must be local or pull"
	}
	if n, err := s.st.GetNode(in.NodeID); err != nil || n.Role != "protect" {
		return "node_id must reference a protect node"
	}
	if p, err := s.st.GetNode(in.PublisherID); err != nil || p.Role != "publish" {
		return "publisher_id must reference a publish agent"
	}
	return ""
}

func (s *Server) handleListSyncProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListSyncProfiles()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if list == nil {
		list = []store.SyncProfile{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateSyncProfile(w http.ResponseWriter, r *http.Request) {
	var in store.SyncProfile
	if !decodeJSON(w, r, &in) {
		return
	}
	if msg := s.validateSyncProfile(&in); msg != "" {
		writeErr(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	user, _ := s.sessionUser(r)
	in.ID = idgen.New("sp_")
	in.Enabled = true
	in.CreatedBy = user
	created, err := s.st.CreateSyncProfile(in)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("sync profile created", "profile", created.ID, "publisher", created.PublisherID, "node", created.NodeID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteSyncProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteSyncProfile(r.PathValue("id")); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "sync profile not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handlePublisherProfiles lists the enabled profiles owned by the calling
// publisher, so `tg-publish sync` only has to trigger them.
func (s *Server) handlePublisherProfiles(w http.ResponseWriter, r *http.Request) {
	publisherID, _ := clientCN(r)
	list, err := s.st.ListSyncProfilesForPublisher(publisherID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if list == nil {
		list = []store.SyncProfile{}
	}
	writeJSON(w, http.StatusOK, list)
}
