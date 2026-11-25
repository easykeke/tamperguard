//go:build linux

package enforcer

import "log/slog"

// platformEnforcer picks the strongest backend this kernel allows.
//
// Order: eBPF LSM (synchronous blocking) -> fanotify (detect and restore) ->
// nil, which makes Select fall back to the observe-only simulator. Each failure
// is logged with its reason so an operator can tell why a node came up degraded.
func platformEnforcer(opts Options) Enforcer {
	if e, err := NewEBPF(opts.PublisherUIDs); err == nil {
		return e
	} else {
		slog.Default().Warn("eBPF LSM backend unavailable, trying fanotify", "err", err)
	}
	if f, err := NewFanotify(opts.StateDir, opts.PublisherUIDs); err == nil {
		return f
	} else {
		slog.Default().Warn("fanotify backend unavailable, falling back to observe", "err", err)
	}
	return nil
}
