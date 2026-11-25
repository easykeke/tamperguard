//go:build linux

package fsverity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestIoctlLayout(t *testing.T) {
	// The ioctl numbers are ABI; a typo compiles but fails at runtime with
	// ENOTTY instead of EOPNOTSUPP, so pin them down.
	if fsIOCEnableVerity != 0x40806685 {
		t.Fatalf("enable ioctl = %#x, want 0x40806685", fsIOCEnableVerity)
	}
	if fsIOCMeasureVerity != 0xC0046686 {
		t.Fatalf("measure ioctl = %#x, want 0xC0046686", fsIOCMeasureVerity)
	}
	if got := unsafe.Sizeof(enableArg{}); got != 128 {
		t.Fatalf("enableArg size = %d, want 128", got)
	}
}

// TestProbeOrUnsupported exercises the real ioctl path. On kernels without
// CONFIG_FS_VERITY (e.g. WSL2) Enable must return ErrUnsupported, which proves
// the ioctl number reached the right kernel handler; on a full kernel it
// enables verity and checks the file becomes read-only.
func TestProbeOrUnsupported(t *testing.T) {
	dir := t.TempDir()
	st := Probe(dir)
	if !st.Supported {
		t.Logf("fs-verity unavailable on this kernel/filesystem: %s", st.Reason)
		if err := enableProbeFile(t, dir); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Enable on an unsupported kernel returned %v, want ErrUnsupported", err)
		}
		return
	}

	path := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Enable(path); err != nil {
		t.Fatalf("enable: %v", err)
	}
	ok, err := IsVerity(path)
	if err != nil || !ok {
		t.Fatalf("IsVerity after enable = %v, %v", ok, err)
	}
	digest, err := Digest(path)
	if err != nil || len(digest) != 64 {
		t.Fatalf("digest = %q, %v", digest, err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a verity file accepted a write")
	}
}

func enableProbeFile(t *testing.T, dir string) error {
	t.Helper()
	f, err := os.CreateTemp(dir, ".tg-verity-probe2-")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)
	return Enable(name)
}
