//go:build !linux && !windows

package enforcer

import "errors"

func platformEnforcer(opts Options) Enforcer { return nil }

func fanotifyEnforcer(opts Options) (Enforcer, error) {
	return nil, errors.New("enforcer: fanotify is Linux only")
}

func windowsACLEnforcer(opts Options) (Enforcer, error) {
	return nil, errors.New("enforcer: windows-acl is Windows only")
}

// Unlock is a Windows-only operator action.
func Unlock(stateDir string) error {
	return errors.New("enforcer: unlock is Windows only")
}
