//go:build windows

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWatchDeliversEvents verifies the ReadDirectoryChangesW wrapper on a real
// directory. It runs without administrator rights.
func TestWatchDeliversEvents(t *testing.T) {
	dir := t.TempDir()
	events := make(chan struct{}, 8)
	w, err := Watch(dir, func() {
		select {
		case events <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	defer w.Close()

	// Give the watcher a moment to start blocking on the handle.
	time.Sleep(150 * time.Millisecond)
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("no directory-change event within 5s")
	}

	// A second change (rename) must also be reported.
	if err := os.Rename(path, filepath.Join(dir, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-events:
			return
		case <-deadline:
			t.Fatal("no event for rename within 5s")
		}
	}
}
