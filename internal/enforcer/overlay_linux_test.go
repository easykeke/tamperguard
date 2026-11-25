//go:build linux

package enforcer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/easykeke/tamperguard/internal/policy"
)

// TestOverlayEnforcement pins the OverlayFS behaviour that matters for
// containers: because enforcement is inode-based and the LSM hooks fire on the
// overlay inode (the one the merged path exposes), indexing the merged tree is
// sufficient. Copy-up changes the underlying inode but the VFS inode the hooks
// see stays the one in the index, and files created inside the tree inherit
// protection through d_instantiate.
//
// Known limit (documented, out of scope): writing directly to the upper/lower
// directories from the host bypasses the overlay index. That requires root on
// the host, which is outside the threat model.
func TestOverlayEnforcement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to mount overlay and attach LSM programs")
	}
	base := t.TempDir()
	lower := filepath.Join(base, "lower")
	upper := filepath.Join(base, "upper")
	work := filepath.Join(base, "work")
	merged := filepath.Join(base, "merged")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "index.html"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(lower, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lower, "sub", "a.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Skipf("overlay mount unavailable: %v", err)
	}
	defer func() { _ = unix.Unmount(merged, unix.MNT_DETACH) }()

	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		t.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()

	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "ovl", Name: "overlay", Version: 1,
		Paths: []policy.PathRule{{Path: merged, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	if err := enf.Update(Runtime{Policy: snap}); err != nil {
		t.Fatalf("update: %v", err)
	}
	defer func() { _ = enf.Update(Runtime{}) }()

	requireBlocked := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was allowed on overlay", what)
		}
		if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) && !errors.Is(err, os.ErrPermission) {
			t.Fatalf("%s failed for an unexpected reason: %v", what, err)
		}
	}

	t.Run("unauthorised mutations blocked on merged path", func(t *testing.T) {
		requireBlocked(t, "overwrite", os.WriteFile(filepath.Join(merged, "index.html"), []byte("evil"), 0o644))
		requireBlocked(t, "create", os.WriteFile(filepath.Join(merged, "new.php"), []byte("x"), 0o644))
		requireBlocked(t, "unlink", os.Remove(filepath.Join(merged, "sub", "a.css")))
		requireBlocked(t, "mkdir", os.Mkdir(filepath.Join(merged, "d2"), 0o755))
		requireBlocked(t, "chmod", os.Chmod(filepath.Join(merged, "index.html"), 0o600))
		requireBlocked(t, "rename", os.Rename(filepath.Join(merged, "index.html"), filepath.Join(merged, "i2.html")))
	})

	t.Run("reads still work", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(merged, "sub", "a.css"))
		if err != nil || string(data) != "body{}" {
			t.Fatalf("read: %q %v", data, err)
		}
	})

	grant := policy.Grant{
		TokenID: "tok-ovl", Subject: "pub", NodeID: "node",
		Paths: []string{merged}, ExpiresAt: time.Now().Unix() + 120,
	}

	t.Run("granted write triggers copy-up and is allowed", func(t *testing.T) {
		if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(merged, "index.html"), []byte("v2"), 0o644); err != nil {
			t.Fatalf("granted write on overlay failed: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(merged, "index.html"))
		if err != nil || string(data) != "v2" {
			t.Fatalf("content after granted write: %q %v", data, err)
		}
	})

	t.Run("after revocation the copied-up file is blocked again", func(t *testing.T) {
		if err := enf.Update(Runtime{Policy: snap}); err != nil {
			t.Fatal(err)
		}
		requireBlocked(t, "overwrite after copy-up", os.WriteFile(filepath.Join(merged, "index.html"), []byte("v3"), 0o644))
		data, _ := os.ReadFile(filepath.Join(merged, "index.html"))
		if string(data) != "v2" {
			t.Fatalf("content changed after revocation: %q", data)
		}
	})

	t.Run("files created under a grant stay protected after revocation", func(t *testing.T) {
		if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
			t.Fatal(err)
		}
		newDir := filepath.Join(merged, "v2", "assets")
		if err := os.MkdirAll(newDir, 0o755); err != nil {
			t.Fatalf("mkdir under grant: %v", err)
		}
		newFile := filepath.Join(newDir, "app.js")
		if err := os.WriteFile(newFile, []byte("console.log(1)"), 0o644); err != nil {
			t.Fatalf("write under grant: %v", err)
		}
		if err := enf.Update(Runtime{Policy: snap}); err != nil {
			t.Fatal(err)
		}
		requireBlocked(t, "write to inherited overlay subtree", os.WriteFile(newFile, []byte("evil"), 0o644))
	})
}
