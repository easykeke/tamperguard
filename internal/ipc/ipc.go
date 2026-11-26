// Package ipc exposes the local control endpoint used by the Windows GUI.
package ipc

// Status is the non-sensitive snapshot served to the tray/window client.
type Status struct {
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

// Request is a line-delimited command from the GUI.
type Request struct {
	Cmd string `json:"cmd"`
}
