//go:build linux

package enforcer

import (
	"os"
	"syscall"
	"testing"
)

// TestKeyEncoding pins the device-number conversion: struct stat reports
// st_dev in new_encode_dev form, while the kernel compares i_sb->s_dev.
func TestKeyEncoding(t *testing.T) {
	fi, err := os.Stat(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	k, ok := keyOf(os.TempDir(), fi)
	if !ok {
		t.Fatal("keyOf failed")
	}
	t.Logf("stat dev=%d ino=%d -> kernel key dev=%d ino=%d", st.Dev, st.Ino, k.Dev, k.Ino)
	u32dev := uint32(st.Dev)
	major := (u32dev >> 8) & 0xfff
	minor := (u32dev & 0xff) | ((u32dev >> 12) & 0xfff00)
	want := (major << 20) | minor
	if k.Dev != want {
		t.Fatalf("dev encoding: got %d want %d", k.Dev, want)
	}
	if major != 0 && k.Dev == u32dev {
		t.Fatalf("conversion is a no-op on a non-zero major device (dev=%d)", st.Dev)
	}
}
