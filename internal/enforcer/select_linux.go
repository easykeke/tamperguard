//go:build linux

package enforcer

import "log/slog"

// platformEnforcer returns the eBPF LSM backend when the running kernel lets us
// attach LSM programs. A failure here is not fatal: the caller falls back to
// the simulation backend, which reports Degraded=true so the control plane
// never counts this node as fully protected.
func platformEnforcer(opts Options) Enforcer {
	e, err := NewEBPF(opts.PublisherUIDs)
	if err != nil {
		slog.Default().Warn("eBPF LSM backend unavailable, falling back to observe", "err", err)
		return nil
	}
	return e
}
