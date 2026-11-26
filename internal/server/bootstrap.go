package server

import (
	"net/http"

	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/token"
)

// handleCreateBootstrapToken mints a one-time enrolment token so the console can
// onboard a protect or publish agent without shelling into the control plane.
// The raw token is returned exactly once; only its digest is stored.
func (s *Server) handleCreateBootstrapToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Role == "" {
		in.Role = "protect"
	}
	if in.Role != "protect" && in.Role != "publish" {
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	raw := idgen.Token(24)
	if err := s.st.AddBootstrapToken(token.DigestString(raw), in.Role); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	user, _ := s.sessionUser(r)
	s.log.Warn("bootstrap token issued", "role", in.Role, "by", user, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusCreated, map[string]string{
		"token": raw,
		"role":  in.Role,
		"note":  "single use; run tg-agent enroll on the host",
	})
}
