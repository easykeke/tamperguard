//go:build !linux

package enforcer

// DetachPinned is a no-op outside Linux (there are no BPF links to detach).
func DetachPinned() (int, error) { return 0, nil }
