//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easykeke/tamperguard/internal/policy"
)

// TestEBPFInheritance proves that a subtree created during a live grant is
// indexed by the kernel itself (d_instantiate), so it is protected and
// grantable immediately rather than after the next userspace sync.
func TestEBPFInheritance(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to attach LSM programs")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "site")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		t.Skipf("eBPF LSM backend unavailable: %v", err)
	}
	defer enf.Close()

	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "pol-inherit", Name: "inherit", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	grant := policy.Grant{
		TokenID: "tok-inherit", Subject: "pub", NodeID: "node",
		Paths: []string{dir}, ExpiresAt: time.Now().Unix() + 120,
	}
	if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
		t.Fatalf("update with grant: %v", err)
	}
	defer func() { _ = enf.Update(Runtime{}) }()

	nested := filepath.Join(dir, "v2", "assets")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir inside granted tree: %v", err)
	}
	target := filepath.Join(nested, "app.js")
	if err := os.WriteFile(target, []byte("console.log(1)"), 0o644); err != nil {
		t.Fatalf("write in freshly created subtree during grant: %v", err)
	}

	// Drop the grant WITHOUT re-walking the tree from userspace: the new
	// subtree must already be protected by kernel-side inheritance.
	if err := enf.Update(Runtime{Policy: snap}); err != nil {
		t.Fatalf("update without grant: %v", err)
	}
	if err := os.WriteFile(target, []byte("evil"), 0o644); err == nil {
		t.Fatal("write to inherited subtree allowed after the grant was removed")
	}
	existing := filepath.Join(nested, "other.js")
	if err := os.WriteFile(existing, []byte("x"), 0o644); err == nil {
		t.Fatal("creation in inherited subtree allowed after the grant was removed")
	}
	if _, err := os.ReadFile(target); err != nil {
		t.Fatalf("read of inherited file blocked: %v", err)
	}
}
