package enforcer

import "fmt"

// Options configures backend selection.
type Options struct {
	// PublisherUIDs are the uids whose processes may consume a live release
	// grant on Linux. The kernel sees uids, not agent identities, so the mapping
	// from "publisher agent" to "operating system user" is explicit.
	PublisherUIDs []int
	// PublisherSIDs is the Windows equivalent: account SIDs (or names) allowed
	// to consume grants while a release token is live.
	PublisherSIDs []string
	// StateDir is where the degraded backends keep their baseline copies.
	StateDir string
	// IntegrityLevel enables the Windows MIC hardening layer (label protected
	// paths High with NO_WRITE_UP in addition to the ACL lockdown).
	IntegrityLevel bool
}

// Select returns the strongest enforcement backend available in this build.
func Select(opts Options) Enforcer {
	if e := platformEnforcer(opts); e != nil {
		return e
	}
	return NewSim()
}

// SelectKind resolves an explicit backend choice.
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
		return fanotifyEnforcer(opts)
	case "windows-acl":
		return windowsACLEnforcer(opts)
	default:
		return nil, fmt.Errorf("enforcer: unknown backend %q (want auto, ebpf, fanotify, windows-acl or observe)", kind)
	}
}
