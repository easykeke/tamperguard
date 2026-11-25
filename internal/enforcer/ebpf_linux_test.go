//go:build linux

package enforcer

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/easykeke/tamperguard/internal/policy"
)

// TestEBPFLSMEnforcement is the proof that this product actually blocks: it
// attaches the real LSM programs and checks that a write to a protected path
// fails with EPERM, that reads still work, that a live grant lets the write
// through, and that removing the grant closes the door again.
//
// It needs root and a kernel with the bpf LSM enabled; it skips otherwise so
// the normal `go test ./...` stays runnable everywhere.
func TestEBPFLSMEnforcement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to attach LSM programs")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "site")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(dir, "index.html")
	if err := os.WriteFile(protected, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		t.Skipf("eBPF LSM backend unavailable: %v", err)
	}
	defer enf.Close()

	snap := &policy.Snapshot{
		Policy: policy.Policy{
			ID: "pol-test", Name: "test", Version: 1,
			Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
		},
	}
	if err := enf.Update(Runtime{Policy: snap}); err != nil {
		t.Fatalf("update: %v", err)
	}
	defer func() {
		// Drop protection before the test framework removes the temp tree,
		// otherwise cleanup itself would be (correctly) denied.
		_ = enf.Update(Runtime{})
	}()

	t.Run("unprotected path still writable", func(t *testing.T) {
		free := filepath.Join(base, "free.txt")
		if err := os.WriteFile(free, []byte("ok"), 0o644); err != nil {
			t.Fatalf("write outside protection failed: %v", err)
		}
	})

	t.Run("protected write denied with EPERM", func(t *testing.T) {
		err := os.WriteFile(protected, []byte("webshell"), 0o644)
		if err == nil {
			t.Fatal("protected write was allowed")
		}
		if !errors.Is(err, syscall.EPERM) && !errors.Is(err, os.ErrPermission) {
			t.Fatalf("expected permission error, got %v", err)
		}
	})

	t.Run("read still allowed", func(t *testing.T) {
		data, err := os.ReadFile(protected)
		if err != nil {
			t.Fatalf("read of protected file failed: %v", err)
		}
		if string(data) != "v1" {
			t.Fatalf("content changed: %q", data)
		}
	})

	t.Run("new file creation denied", func(t *testing.T) {
		err := os.WriteFile(filepath.Join(dir, "shell.php"), []byte("<?php ?>"), 0o644)
		if err == nil {
			t.Fatal("creation of a new file in a protected dir was allowed")
		}
	})

	t.Run("unlink denied", func(t *testing.T) {
		if err := os.Remove(protected); err == nil {
			t.Fatal("delete of a protected file was allowed")
		}
	})

	t.Run("live grant allows write", func(t *testing.T) {
		now := time.Now().Unix()
		rt := Runtime{Policy: snap, Grants: []policy.Grant{{
			TokenID: "tok_test", Subject: "pub_test", NodeID: "node_test",
			Paths: []string{dir}, ExpiresAt: now + 120,
		}}}
		if err := enf.Update(rt); err != nil {
			t.Fatalf("update with grant: %v", err)
		}
		if err := os.WriteFile(protected, []byte("v2"), 0o644); err != nil {
			t.Fatalf("granted write failed: %v", err)
		}
	})

	t.Run("removing the grant closes the door again", func(t *testing.T) {
		if err := enf.Update(Runtime{Policy: snap}); err != nil {
			t.Fatalf("update without grant: %v", err)
		}
		if err := os.WriteFile(protected, []byte("v3"), 0o644); err == nil {
			t.Fatal("write allowed after grant removal")
		}
	})

	t.Run("blocked events reach userspace", func(t *testing.T) {
		deadline := time.After(2 * time.Second)
		for {
			select {
			case ev := <-enf.Events():
				if ev.Kind == "write.blocked" {
					return
				}
			case <-deadline:
				t.Fatal("no blocked event observed")
			}
		}
	})

	t.Run("observe rule records without blocking", func(t *testing.T) {
		observeOnly := &policy.Snapshot{Policy: policy.Policy{
			ID: "pol-observe", Name: "observe", Version: 1,
			Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeObserve}},
		}}
		if err := enf.Update(Runtime{Policy: observeOnly}); err != nil {
			t.Fatalf("update observe: %v", err)
		}
		if err := os.WriteFile(protected, []byte("observed-write"), 0o644); err != nil {
			t.Fatalf("observe mode must not block the write: %v", err)
		}
		deadline := time.After(2 * time.Second)
		for {
			select {
			case ev := <-enf.Events():
				if ev.Kind == "write.observed" {
					return
				}
			case <-deadline:
				t.Fatal("no write.observed event")
			}
		}
	})
}
