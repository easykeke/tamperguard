//go:build linux

package enforcer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/policy"
)

// TestFanotifyRestore covers the degraded backend end to end: unauthorised
// writes are reverted, creations are removed, deletions are restored, and an
// authorised publisher uid with a live grant is allowed to publish (its content
// becomes the new baseline).
func TestFanotifyRestore(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify")
	}
	// Creations and deletions are recovered by the periodic scan, so make it
	// fast for the test.
	t.Setenv("TG_FAN_SCAN_SECONDS", "1")
	dir := t.TempDir()
	stateDir := t.TempDir()
	protected := filepath.Join(dir, "index.html")
	if err := os.WriteFile(protected, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := NewFanotify(stateDir, []int{os.Getuid()})
	if err != nil {
		t.Skipf("fanotify unavailable: %v", err)
	}
	defer f.Close()

	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "pol-fanotify", Name: "fanotify", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	if err := f.Update(Runtime{Policy: snap}); err != nil {
		t.Fatalf("update: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // let the reads/marks settle

	runSh := func(script string) {
		cmd := exec.Command("sh", "-c", script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Logf("sh %q returned %v: %s", script, err, out)
		}
	}
	waitContent := func(want string) {
		deadline := time.Now().Add(4 * time.Second)
		for {
			data, err := os.ReadFile(protected)
			if err == nil && strings.TrimSpace(string(data)) == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("file content did not become %q, got %q (err=%v)", want, data, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	t.Run("unauthorised overwrite is reverted", func(t *testing.T) {
		runSh("echo evil > " + protected)
		waitContent("v1")
	})

	t.Run("unauthorised creation is removed", func(t *testing.T) {
		newFile := filepath.Join(dir, "shell.php")
		runSh("echo '<?php ?>' > " + newFile)
		deadline := time.Now().Add(6 * time.Second)
		for {
			if _, err := os.Lstat(newFile); os.IsNotExist(err) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("created file was not removed by the scan")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("unauthorised deletion is restored", func(t *testing.T) {
		runSh("rm -f " + protected)
		deadline := time.Now().Add(6 * time.Second)
		for {
			data, err := os.ReadFile(protected)
			if err == nil && strings.TrimSpace(string(data)) == "v1" {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("deleted file was not restored by the scan")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	t.Run("authorised publisher uid with grant may write", func(t *testing.T) {
		grant := policy.Grant{
			TokenID: "tok-fanotify", Subject: "pub", NodeID: "node",
			Paths: []string{dir}, ExpiresAt: time.Now().Unix() + 120,
		}
		if err := f.Update(Runtime{Policy: snap, Grants: []policy.Grant{grant}}); err != nil {
			t.Fatal(err)
		}
		runSh("echo v2 > " + protected)
		waitContent("v2")
		// The close event that folds v2 into the baseline is asynchronous; let
		// it land before the next step revokes the grant.
		time.Sleep(400 * time.Millisecond)
	})

	t.Run("after the grant is removed writes are reverted to the new baseline", func(t *testing.T) {
		if err := f.Update(Runtime{Policy: snap}); err != nil {
			t.Fatal(err)
		}
		runSh("echo v3 > " + protected)
		waitContent("v2")
	})

	t.Run("blocked events are reported", func(t *testing.T) {
		deadline := time.After(2 * time.Second)
		for {
			select {
			case ev := <-f.Events():
				if ev.Kind == audit.KindWriteBlocked {
					return
				}
			case <-deadline:
				t.Fatal("no blocked event observed")
			}
		}
	})
}
