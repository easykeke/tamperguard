//go:build windows

package agent

import (
	"time"

	"github.com/easykeke/tamperguard/internal/ipc"
)

// snapshot builds the IPC status response.
func (a *Agent) snapshot() ipc.Status {
	capb := a.enf.Capability()
	return ipc.Status{
		AgentID:       a.state.AgentID,
		Role:          a.state.Role,
		Version:       Version,
		Enforcer:      a.enf.Name(),
		Degraded:      capb.Degraded,
		PolicyDigest:  a.policyDigest,
		ServerURL:     a.state.ServerURL,
		LastHeartbeat: time.Now().Unix(),
	}
}

func (a *Agent) startIPC() {
	ipc.Serve(a.snapshot)
}
