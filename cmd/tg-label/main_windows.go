//go:build windows

// tg-label applies or resets the strict Windows protection (DACL + integrity
// label) on a single path. It is the helper the on-host MIC demo runs as a SYSTEM
// task: only a SYSTEM process can label an object System, and the demo then
// attempts writes from an elevated administrator session.
//
//	tg-label apply --path C:\dir --level system --state C:\state
//	tg-label reset --path C:\dir --state C:\state
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/token"
)

func main() {
	mode := flag.String("mode", "apply", "apply or reset")
	path := flag.String("path", "", "target path")
	level := flag.String("level", "system", "integrity level: system, high, medium or off")
	state := flag.String("state", "", "state directory")
	flag.Parse()

	if *path == "" || *state == "" {
		fmt.Println("ERROR: --path and --state are required")
		os.Exit(2)
	}
	abs, err := filepath.Abs(*path)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}
	switch *mode {
	case "apply":
		if err := apply(abs, *level, *state); err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(1)
		}
		fmt.Println("applied")
	case "reset":
		_ = enforcer.Unlock(*state)
		out, err := exec.Command("icacls.exe", abs, "/reset", "/T", "/C").CombinedOutput()
		if err != nil {
			fmt.Printf("ERROR: icacls reset: %v (%s)\n", err, string(out))
			os.Exit(1)
		}
		fmt.Println("reset")
	default:
		fmt.Println("ERROR: --mode must be apply or reset")
		os.Exit(2)
	}
}

func apply(path, level, state string) error {
	eng, err := enforcer.SelectKind("windows-acl", enforcer.Options{
		StateDir:       state,
		IntegrityLevel: level,
	})
	if err != nil {
		return err
	}
	defer eng.Close()
	norm, ok := token.NormalizePath(path)
	if !ok {
		return fmt.Errorf("invalid path %q", path)
	}
	rt := enforcer.Runtime{Policy: &policy.Snapshot{Policy: policy.Policy{
		Name:  "label-helper",
		Paths: []policy.PathRule{{Path: norm, Recursive: true, Mode: policy.ModeEnforce}},
	}}}
	if err := eng.Update(rt); err != nil {
		return err
	}
	if err := eng.Health(); err != nil {
		return fmt.Errorf("protection did not apply: %w", err)
	}
	return nil
}
