package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/store"
	"github.com/easykeke/tamperguard/internal/uninstall"
)

// Uninstall workflow
//
// There are exactly two ways to remove an agent, and both go through the control
// plane:
//
//  1. an administrator triggers the uninstall from the management plane
//     (POST /nodes/{id}/uninstall) -> the control plane signs a ticket and pushes
//     it to the node;
//  2. the operator runs `tg-agent uninstall` on the host: the agent creates a
//     request with a random nonce, the request waits for an administrator, and
//     the approval returns a ticket bound to that nonce. Only a ticket that
//     verifies against the control-plane policy key authorises removal.

// handleUninstallRequest stores a client-initiated uninstall request.
func (s *Server) handleUninstallRequest(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	var in struct {
		Nonce  string `json:"nonce"`
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Nonce) < 8 || len(in.Nonce) > 128 {
		writeErr(w, http.StatusBadRequest, "invalid", "nonce must be 8..128 characters")
		return
	}
	if len(in.Reason) > 512 {
		in.Reason = in.Reason[:512]
	}
	req, err := s.st.CreateUninstallRequest(store.UninstallRequest{
		ID:     idgen.New("ur_"),
		NodeID: nodeID,
		Nonce:  in.Nonce,
		Reason: in.Reason,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Warn("uninstall requested by host", "request", req.ID, "node", nodeID, "reason", in.Reason)
	writeJSON(w, http.StatusCreated, map[string]string{
		"request_id": req.ID,
		"status":     req.Status,
	})
}

// handleUninstallStatus lets the requesting agent poll for the decision.
func (s *Server) handleUninstallStatus(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	req, err := s.st.GetUninstallRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "uninstall request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.NodeID != nodeID {
		writeErr(w, http.StatusForbidden, "forbidden", "request belongs to another node")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": req.ID,
		"status":     req.Status,
		"ticket":     req.Ticket,
	})
}

// handleListUninstallRequests lists requests for the management plane.
func (s *Server) handleListUninstallRequests(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListUninstallRequests(r.URL.Query().Get("status"), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if list == nil {
		list = []store.UninstallRequest{}
	}
	writeJSON(w, http.StatusOK, list)
}

// approveUninstall signs a ticket for a request and pushes it to the node.
func (s *Server) approveUninstall(req store.UninstallRequest, by string) (string, error) {
	tk := &uninstall.Ticket{NodeID: req.NodeID, RequestID: req.ID, Nonce: req.Nonce}
	if err := uninstall.Sign(s.policyPriv, tk); err != nil {
		return "", err
	}
	enc, err := uninstall.EncodeTicket(tk)
	if err != nil {
		return "", err
	}
	if err := s.st.DecideUninstall(req.ID, uninstall.StatusApproved, enc, by); err != nil {
		return "", err
	}
	payload, _ := json.Marshal(map[string]string{"ticket": enc})
	s.hub.Publish(req.NodeID, Event{
		Kind:    EventUninstall,
		NodeID:  req.NodeID,
		At:      time.Now().Unix(),
		Payload: payload,
	})
	s.log.Warn("uninstall approved", "request", req.ID, "node", req.NodeID, "by", by)
	return enc, nil
}

// handleApproveUninstall approves a pending request and returns the ticket.
func (s *Server) handleApproveUninstall(w http.ResponseWriter, r *http.Request) {
	req, err := s.st.GetUninstallRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "uninstall request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.Status != uninstall.StatusPending {
		writeErr(w, http.StatusConflict, "conflict", "request is "+req.Status)
		return
	}
	user, _ := s.sessionUser(r)
	ticket, err := s.approveUninstall(req, user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": req.ID,
		"status":     uninstall.StatusApproved,
		"ticket":     ticket,
	})
}

// handleDenyUninstall denies a pending request.
func (s *Server) handleDenyUninstall(w http.ResponseWriter, r *http.Request) {
	req, err := s.st.GetUninstallRequest(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "uninstall request not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.Status != uninstall.StatusPending {
		writeErr(w, http.StatusConflict, "conflict", "request is "+req.Status)
		return
	}
	user, _ := s.sessionUser(r)
	if err := s.st.DecideUninstall(req.ID, uninstall.StatusDenied, "", user); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Warn("uninstall denied", "request", req.ID, "node", req.NodeID, "by", user)
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": req.ID,
		"status":     uninstall.StatusDenied,
	})
}

// handleNodeUninstall is the management-plane path: the administrator removes an
// agent without anyone touching the host. The ticket is signed immediately and
// pushed over the stream (the node also sees it on its next request).
func (s *Server) handleNodeUninstall(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	node, err := s.st.GetNode(nodeID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if node.Role != "protect" {
		writeErr(w, http.StatusBadRequest, "invalid", "only protect agents can be uninstalled")
		return
	}
	user, _ := s.sessionUser(r)
	nonce, err := uninstall.Nonce()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	req, err := s.st.CreateUninstallRequest(store.UninstallRequest{
		ID:     idgen.New("ur_"),
		NodeID: nodeID,
		Nonce:  nonce,
		Reason: "initiated from the management plane by " + user,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ticket, err := s.approveUninstall(req, user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"request_id": req.ID,
		"status":     uninstall.StatusApproved,
		"ticket":     ticket,
	})
}
