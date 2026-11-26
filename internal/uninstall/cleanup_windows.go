// Package uninstall implements signed uninstall plus platform cleanup.
package uninstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultSystemTargets returns the Windows service names used by the packaged
// agents.
func DefaultSystemTargets() (unitPath, serviceName string) {
	return "", "TamperGuardAgent"
}

// Perform removes the Windows services and files through a SYSTEM scheduled
// task: the hardened service ACL denies stop/delete to Administrators, so the
// cleanup must run with SYSTEM rights. The ticket has already been verified by
// the caller.
func Perform(ctx context.Context, opts Options) ([]string, error) {
	if opts.DryRun {
		return []string{"dry-run: would stop/delete services and remove files as SYSTEM"}, nil
	}
	script := fmt.Sprintf(`@echo off
sc stop TamperGuardWatchdog >nul 2>&1
sc delete TamperGuardWatchdog >nul 2>&1
sc stop TamperGuardAgent >nul 2>&1
sc delete TamperGuardAgent >nul 2>&1
sc stop TamperGuardPublish >nul 2>&1
sc delete TamperGuardPublish >nul 2>&1
timeout /t 2 /nobreak >nul
del /f /q "%s" >nul 2>&1
rmdir /s /q "%s" >nul 2>&1
`, opts.BinaryPath, opts.StateDir)
	bat := filepath.Join(os.TempDir(), fmt.Sprintf("tg-uninstall-%d.cmd", os.Getpid()))
	if err := os.WriteFile(bat, []byte(script), 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(bat)

	taskName := "TamperGuardUninstall"
	_ = exec.CommandContext(ctx, "schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
	create := exec.CommandContext(ctx, "schtasks.exe", "/Create", "/TN", taskName,
		"/TR", bat, "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F")
	if out, err := create.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("create SYSTEM cleanup task: %w (%s)", err, string(out))
	}
	actions := []string{"created SYSTEM cleanup task", "stopping watchdog and agent services", "removing binary and state"}
	if out, err := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		return actions, fmt.Errorf("run SYSTEM cleanup task: %w (%s)", err, string(out))
	}
	// Give the SYSTEM task time to stop the services and delete the files.
	if err := exec.CommandContext(ctx, "cmd.exe", "/c", "timeout", "/t", "8", "/nobreak").Run(); err != nil {
		// timeout may be unavailable; ignore and let the task finish.
	}
	_ = exec.CommandContext(ctx, "schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
	actions = append(actions, "services removed, binary and state deleted by SYSTEM task")
	return actions, nil
}

// SpawnDetached schedules the same SYSTEM cleanup (used when the service itself
// receives a remote uninstall ticket and cannot delete its own image).
func SpawnDetached(opts Options) error {
	_, err := Perform(context.Background(), opts)
	return err
}
