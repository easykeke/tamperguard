//go:build windows

package enforcer

import "errors"

// platformEnforcer on Windows uses the ACL lockdown backend: there is no eBPF
// LSM or fanotify equivalent in user mode, and a filesystem minifilter needs a
// signed kernel driver.
func platformEnforcer(opts Options) Enforcer {
	e, err := NewWindowsACL(WindowsACLConfig{
		PublisherSIDs:  opts.PublisherSIDs,
		StateDir:       opts.StateDir,
		IntegrityLevel: opts.IntegrityLevel,
		AllowAdmins:    opts.AllowAdmins,
	})
	if err != nil {
		return nil
	}
	return e
}

func fanotifyEnforcer(opts Options) (Enforcer, error) {
	return nil, errors.New("enforcer: fanotify is Linux only")
}

func windowsACLEnforcer(opts Options) (Enforcer, error) {
	return NewWindowsACL(WindowsACLConfig{
		PublisherSIDs:  opts.PublisherSIDs,
		StateDir:       opts.StateDir,
		IntegrityLevel: opts.IntegrityLevel,
		AllowAdmins:    opts.AllowAdmins,
	})
}
