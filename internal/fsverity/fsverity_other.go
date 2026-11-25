//go:build !linux

package fsverity

// IsVerity is only meaningful on Linux.
func IsVerity(path string) (bool, error) { return false, ErrUnsupported }

// Enable is a no-op error on platforms without fs-verity.
func Enable(path string) error { return ErrUnsupported }

// Digest is unavailable on platforms without fs-verity.
func Digest(path string) (string, error) { return "", ErrUnsupported }

// Probe reports fs-verity as unavailable.
func Probe(dir string) Status { return Status{Reason: ErrUnsupported.Error()} }
