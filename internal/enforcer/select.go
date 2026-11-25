package enforcer

import "fmt"

// Options configures backend selection.
type Options struct {
	// PublisherUIDs are the uids whose processes may consume a live release
	// grant. The kernel sees uids, not agent identities, so the mapping from
	// "publisher agent" to "operating system user" is explicit configuration.
	PublisherUIDs []int
	// StateDir is where the degraded backend keeps its baseline copies.
	StateDir string
}

// Select returns the strongest enforcement backend available in this build.
//
// Platform-specific backends (eBPF LSM, fanotify) live in build-tagged files.
// When none is compiled in or usable, the simulation backend is returned and
// its Capability reports Degraded=true, so the control plane can mark the node
// as weak protection instead of silently pretending it is protected.
func Select(opts Options) Enforcer {
	if e := platformEnforcer(opts); e != nil {
		return e
	}
	return NewSim()
}

// SelectKind resolves an explicit backend choice. Operators should keep "auto"
// in production; explicit values exist for testing and for hosts where a
// deliberately weaker mode is wanted.
func SelectKind(kind string, opts Options) (Enforcer, error) {
	switch kind {
	case "", "auto":
		return Select(opts), nil
	case "observe", "sim":
		return NewSim(), nil
	case "ebpf", "ebpf-lsm":
		if e := platformEnforcer(opts); e != nil {
			return e, nil
		}
		return nil, ErrNoBackend
	case "fanotify":
		f, err := NewFanotify(opts.StateDir, opts.PublisherUIDs)
		if err != nil {
			return nil, err
		}
		return f, nil
	default:
		return nil, fmt.Errorf("enforcer: unknown backend %q (want auto, ebpf, fanotify or observe)", kind)
	}
}
