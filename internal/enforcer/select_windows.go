//go:build windows

package enforcer

import "errors"

// platformEnforcer on Windows uses the ACL lockdown backend: there is no eBPF
// LSM or fanotify equivalent in user mode, and a filesystem minifilter needs a
// signed kernel driver.
func platformEnforcer(opts Options) Enforcer {
	e, err := NewWindowsACL(opts.PublisherSIDs, opts.StateDir, opts.IntegrityLevel)
	if err != nil {
		return nil
	}
	return e
}

func fanotifyEnforcer(opts Options) (Enforcer, error) {
	return nil, errors.New("enforcer: fanotify is Linux only")
}

func windowsACLEnforcer(opts Options) (Enforcer, error) {
	return NewWindowsACL(opts.PublisherSIDs, opts.StateDir, opts.IntegrityLevel)
}
