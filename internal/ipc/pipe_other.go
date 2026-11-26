//go:build !windows

package ipc

import "errors"

// Serve is a no-op outside Windows.
func Serve(func() Status) {}

// ErrUnsupported marks the IPC endpoint as Windows-only.
var ErrUnsupported = errors.New("ipc: only supported on Windows")
