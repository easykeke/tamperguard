package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/easykeke/tamperguard/internal/tpmquote"
)

type attestNonce struct {
	nodeID  string
	expires int64
}

// issueAttestNonce creates a fresh quote challenge for a node. Only the latest
// nonce per node is kept; older ones are dropped as they are issued.
func (s *Server) issueAttestNonce(nodeID string) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(buf)
	s.attestMu.Lock()
	defer s.attestMu.Unlock()
	for k, v := range s.attestNonces {
		if v.nodeID == nodeID || s.now().Unix() > v.expires {
			delete(s.attestNonces, k)
		}
	}
	s.attestNonces[nonce] = attestNonce{nodeID: nodeID, expires: s.now().Unix() + 300}
	return nonce
}

// consumeAttestNonce validates and burns a nonce (single use per quote).
func (s *Server) consumeAttestNonce(nodeID, nonce string) bool {
	s.attestMu.Lock()
	defer s.attestMu.Unlock()
	v, ok := s.attestNonces[nonce]
	if !ok || v.nodeID != nodeID || s.now().Unix() > v.expires {
		return false
	}
	delete(s.attestNonces, nonce)
	return true
}

// handleAttestation verifies a TPM quote produced by the agent.
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	nodeID, _ := clientCN(r)
	var in struct {
		Nonce     string `json:"nonce"`
		Attest    string `json:"attest"`
		Signature string `json:"signature"`
		PCR       string `json:"pcr"`
		Indexes   []int  `json:"indexes"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Nonce == "" || in.Attest == "" || in.Signature == "" || in.PCR == "" {
		writeErr(w, http.StatusBadRequest, "invalid", "nonce, attest, signature and pcr are required")
		return
	}
	if !s.consumeAttestNonce(nodeID, in.Nonce) {
		writeErr(w, http.StatusBadRequest, "stale_nonce", "nonce is unknown, expired or already used")
		return
	}
	n, err := s.st.GetNode(nodeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "node not found")
		return
	}
	if n.AKPub == "" {
		writeErr(w, http.StatusBadRequest, "no_ak", "no TPM attestation key registered for this node")
		return
	}
	ak, err := tpmquote.ParseAKPEM([]byte(n.AKPub))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "registered AK unusable: "+err.Error())
		return
	}
	attest, err1 := base64.StdEncoding.DecodeString(in.Attest)
	sig, err2 := base64.StdEncoding.DecodeString(in.Signature)
	pcr, err3 := base64.StdEncoding.DecodeString(in.PCR)
	if err1 != nil || err2 != nil || err3 != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "attest, signature and pcr must be base64")
		return
	}
	nonce, err := hex.DecodeString(in.Nonce)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", "nonce must be hex")
		return
	}
	indexes := in.Indexes
	if len(indexes) == 0 {
		indexes = []int{0, 4, 7}
	}
	ev := tpmquote.Evidence{Attest: attest, Signature: sig, PCR: pcr, Indexes: indexes}
	if err := tpmquote.Verify(ak, nonce, ev); err != nil {
		s.log.Warn("TPM quote rejected", "node", nodeID, "err", err)
		writeErr(w, http.StatusBadRequest, "invalid_quote", err.Error())
		return
	}
	sum := sha256.Sum256(attest)
	summary, _ := json.Marshal(map[string]any{
		"verified":    true,
		"verified_at": s.now().Unix(),
		"indexes":     indexes,
		"quote_sha":   hex.EncodeToString(sum[:]),
	})
	if err := s.st.SetNodeAttestation(nodeID, string(summary)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("TPM quote verified", "node", nodeID, "indexes", indexes)
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

var _ = time.Now
