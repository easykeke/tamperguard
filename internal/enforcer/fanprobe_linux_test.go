//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFanMaskProbe finds which mark masks this kernel accepts. Diagnostic only.
func TestFanMaskProbe(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	defer unix.Close(fd)

	dir := filepath.Join(t.TempDir(), "d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mountpoint := mountPointOf(dir)
	t.Logf("dir=%s mountpoint=%s", dir, mountpoint)

	type c struct {
		name   string
		flags  uint
		mask   uint64
		target string
	}
	cases := []c{
		{"inode CREATE", unix.FAN_MARK_ADD, unix.FAN_CREATE, dir},
		{"inode CREATE|CHILD", unix.FAN_MARK_ADD, unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD, dir},
		{"mount CREATE", unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT, unix.FAN_CREATE, mountpoint},
		{"mount full", unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT, fanotifyMask, mountpoint},
		{"fs full", unix.FAN_MARK_ADD | unix.FAN_MARK_FILESYSTEM, fanotifyMask, mountpoint},
	}
	for i, tc := range cases {
		// Remove any previous mark so each case starts clean.
		_ = unix.FanotifyMark(fd, unix.FAN_MARK_FLUSH, tc.mask, unix.AT_FDCWD, tc.target)
		err := unix.FanotifyMark(fd, tc.flags, tc.mask, unix.AT_FDCWD, tc.target)
		t.Logf("case %d %-22s flags=0x%-6x mask=0x%-10x err=%v", i, tc.name, tc.flags, tc.mask, err)
	}
}

// mountPointOf walks up until the parent device differs.
func mountPointOf(path string) string {
	abs, _ := filepath.Abs(path)
	var curDev uint64
	for p := abs; ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			return abs
		}
		if curDev == 0 {
			curDev = uint64(st.Dev)
		} else if uint64(st.Dev) != curDev {
			return p
		}
		if p == "/" {
			return "/"
		}
	}
}
