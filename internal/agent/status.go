package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// TrayStatus is the small, non-sensitive snapshot the tray UI reads. It is
// written to a directory that normal users can read; no credentials or paths
// that matter to an attacker are included.
type TrayStatus struct {
	AgentID       string `json:"agent_id"`
	Role          string `json:"role"`
	Version       string `json:"version"`
	Enforcer      string `json:"enforcer"`
	Degraded      bool   `json:"degraded"`
	PolicyDigest  string `json:"policy_digest"`
	ServerURL     string `json:"server_url"`
	LastHeartbeat int64  `json:"last_heartbeat"`
	Error         string `json:"error,omitempty"`
}

// writeTrayStatus publishes the snapshot used by the tray UI.
func (a *Agent) writeTrayStatus() {
	if a.opts.StatusDir == "" {
		return
	}
	capb := a.enf.Capability()
	status := TrayStatus{
		AgentID:       a.state.AgentID,
		Role:          a.state.Role,
		Version:       Version,
		Enforcer:      a.enf.Name(),
		Degraded:      capb.Degraded,
		PolicyDigest:  a.policyDigest,
		ServerURL:     a.state.ServerURL,
		LastHeartbeat: time.Now().Unix(),
	}
	if err := os.MkdirAll(a.opts.StatusDir, 0o755); err != nil {
		return
	}
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(a.opts.StatusDir, "status.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
