//go:build !linux

package enforcer

// platformEnforcer returns nil on non-Linux platforms: there is no kernel
// backend to select.
func platformEnforcer(opts Options) Enforcer { return nil }
