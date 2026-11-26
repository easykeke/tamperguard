//go:build windows

package uninstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultSystemTargets returns the Windows service name used by the packaged
// agent (the unit path is unused on Windows).
func DefaultSystemTargets() (unitPath, serviceName string) {
	return "", "TamperGuardAgent"
}

// Perform stops and deletes the service and schedules removal of the binary and
// state directory (a running image cannot be deleted, so the deletion runs from a
// detached helper after this process exits).
func Perform(ctx context.Context, opts Options) ([]string, error) {
	if opts.DryRun {
		return []string{"dry-run: would stop and delete the service, remove the binary and " + opts.StateDir}, nil
	}
	service := opts.ServiceName
	if service == "" {
		_, service = DefaultSystemTargets()
	}
	var actions []string
	for _, args := range [][]string{{"stop", service}, {"delete", service}} {
		out, err := exec.CommandContext(ctx, "sc.exe", args...).CombinedOutput()
		if err != nil {
			actions = append(actions, fmt.Sprintf("sc %v: %v (%s)", args, err, string(out)))
		} else {
			actions = append(actions, "sc "+args[0]+" "+service)
		}
	}
	// A small batch waits for this process to exit, then removes the files.
	bat := fmt.Sprintf("@echo off\r\ntimeout /t 3 /nobreak >nul\r\ndel /f /q \"%s\" >nul 2>&1\r\nrmdir /s /q \"%s\" >nul 2>&1\r\n",
		opts.BinaryPath, opts.StateDir)
	batPath := filepath.Join(os.TempDir(), fmt.Sprintf("tg-uninstall-%d.bat", os.Getpid()))
	if err := os.WriteFile(batPath, []byte(bat), 0o600); err != nil {
		return actions, err
	}
	cmd := exec.Command("cmd.exe", "/c", "start", "/b", "", batPath)
	if err := cmd.Start(); err != nil {
		return actions, err
	}
	actions = append(actions, "deferred removal scheduled for binary and state")
	return actions, nil
}

// SpawnDetached schedules the helper and returns immediately. The agent process
// is the service itself, so it must exit before sc.exe stops it; the helper waits
// three seconds and then stops/deletes the service and removes the files.
func SpawnDetached(opts Options) error {
	service := opts.ServiceName
	if service == "" {
		_, service = DefaultSystemTargets()
	}
	bat := fmt.Sprintf("@echo off\r\ntimeout /t 3 /nobreak >nul\r\nsc stop %s >nul 2>&1\r\nsc delete %s >nul 2>&1\r\ndel /f /q \"%s\" >nul 2>&1\r\nrmdir /s /q \"%s\" >nul 2>&1\r\n",
		service, service, opts.BinaryPath, opts.StateDir)
	batPath := filepath.Join(os.TempDir(), fmt.Sprintf("tg-remote-uninstall-%d.bat", os.Getpid()))
	if err := os.WriteFile(batPath, []byte(bat), 0o600); err != nil {
		return err
	}
	return exec.Command("cmd.exe", "/c", "start", "/b", "", batPath).Start()
}
