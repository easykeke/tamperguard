package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookieName = "tg_session"
	sessionTTL        = 12 * time.Hour
	sessionVersion    = "v1"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Always run a full KDF, even for unknown users, so that response time
	// does not reveal whether the account exists.
	validUser := hmac.Equal([]byte(req.Username), []byte(s.authUser()))
	hash := s.cfg.AdminPasswordHash
	if !validUser {
		hash = dummyHash
	}
	ok := VerifyPassword(hash, req.Password)
	if !validUser || !ok {
		s.log.Warn("login rejected", "user", req.Username, "remote", r.RemoteAddr)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.newSession(req.Username),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	s.log.Info("login accepted", "user", req.Username, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, userResponse{Username: req.Username, Role: "admin"})
}

func (s *Server) authUser() string {
	if s.cfg.AdminUser == "" {
		return "admin"
	}
	return s.cfg.AdminUser
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := s.sessionUser(r)
	writeJSON(w, http.StatusOK, userResponse{Username: user, Role: "admin"})
}

// newSession returns "<payload>.<hmac>" where payload is version|user|expiry.
func (s *Server) newSession(user string) string {
	exp := s.now().Add(sessionTTL).Unix()
	payload := fmt.Sprintf("%s|%s|%d", sessionVersion, user, exp)
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sessionUser validates the cookie and returns the username.
func (s *Server) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 3 || fields[0] != sessionVersion {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(fields[2], "%d", &exp); err != nil {
		return "", false
	}
	if s.now().Unix() > exp {
		return "", false
	}
	if fields[1] != s.authUser() {
		return "", false
	}
	return fields[1], true
}
