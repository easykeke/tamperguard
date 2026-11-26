//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easykeke/tamperguard/internal/policy"
)

// TestEBPFPublisherUIDUpdate proves that process writer rules (translated into
// uids by the agent) take effect without restarting, and that removing the uid
// closes the door again.
func TestEBPFPublisherUIDUpdate(t *testing.T) {
	cleanupPins(t)
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "index.html")
	if err := os.WriteFile(file, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	enf, err := NewEBPF(nil) // no uid allowed yet
	if err != nil {
		t.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()
	defer func() { _ = enf.Update(Runtime{}) }()

	uid := os.Getuid()
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "uid", Name: "uid", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	grant := policy.Grant{
		TokenID: "tok-uid", Subject: "pub", NodeID: "node",
		Paths: []string{dir}, ExpiresAt: time.Now().Unix() + 120,
	}
	if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("v2"), 0o644); err == nil {
		t.Fatal("write allowed although no uid was configured to consume the grant")
	}

	// Configuring the uid must be followed by an Update so the grant map is
	// built with that uid (the agent does this in one sync).
	if err := enf.SetPublisherUIDs([]int{uid}); err != nil {
		t.Fatal(err)
	}
	if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("v2"), 0o644); err != nil {
		t.Fatalf("write should be allowed after the uid was configured: %v", err)
	}

	if err := enf.SetPublisherUIDs(nil); err != nil {
		t.Fatal(err)
	}
	if err := enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("v3"), 0o644); err == nil {
		t.Fatal("write allowed after the uid was removed")
	}
}
