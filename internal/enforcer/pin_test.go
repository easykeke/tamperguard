package enforcer

import "testing"

// cleanupPins clears pins left by earlier runs and disables pinning for this
// test, so t.TempDir cleanup is not blocked by the kernel after Close.
func cleanupPins(t *testing.T) {
	t.Helper()
	_, _ = DetachPinned()
	t.Setenv("TG_EBPF_PIN", "0")
}
