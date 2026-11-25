//go:build windows

// watch-smoke is a tiny on-host check for the directory watcher: it watches a
// temporary directory, creates and renames a file, and expects events.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/easykeke/tamperguard/internal/watch"
)

func main() {
	base := flag.String("dir", ".", "directory to create the sandbox in")
	flag.Parse()
	root, err := filepath.Abs(*base)
	if err != nil {
		fmt.Println("FAIL: abs:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp(root, "watch-sandbox-")
	if err != nil {
		fmt.Println("FAIL: temp dir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	events := make(chan struct{}, 16)
	w, err := watch.Watch(dir, func() {
		select {
		case events <- struct{}{}:
		default:
		}
	})
	if err != nil {
		fmt.Println("FAIL: watch:", err)
		os.Exit(1)
	}
	defer w.Close()
	time.Sleep(200 * time.Millisecond)

	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		fmt.Println("FAIL: write:", err)
		os.Exit(1)
	}
	select {
	case <-events:
		fmt.Println("PASS: create event received")
	case <-time.After(5 * time.Second):
		fmt.Println("FAIL: no event for create within 5s")
		os.Exit(1)
	}

	if err := os.Rename(path, filepath.Join(dir, "renamed.txt")); err != nil {
		fmt.Println("FAIL: rename:", err)
		os.Exit(1)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-events:
			fmt.Println("PASS: rename event received")
			_ = w.Close()
			_ = os.RemoveAll(dir)
			fmt.Println("RESULT: PASS")
			os.Exit(0)
		case <-deadline:
			fmt.Println("FAIL: no event for rename within 5s")
			os.Exit(1)
		}
	}
}
