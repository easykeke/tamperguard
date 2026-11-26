//go:build linux

package uninstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/easykeke/tamperguard/internal/enforcer"
)

// DefaultSystemTargets returns the systemd unit and service names used by the
// packaged agent.
func DefaultSystemTargets() (unitPath, serviceName string) {
	return "/etc/systemd/system/tamperguard-agent.service", "tamperguard-agent"
}

// Perform removes the agent: stop and disable the service, delete the unit file,
// the binary and the state directory. It is only reached after a ticket from the
// control plane has been verified by the caller.
func Perform(ctx context.Context, opts Options) ([]string, error) {
	if opts.DryRun {
		return []string{"dry-run: would stop the service, delete the unit, the binary and " + opts.StateDir}, nil
	}
	unit, service := opts.UnitPath, opts.ServiceName
	if unit == "" || service == "" {
		u, s := DefaultSystemTargets()
		if unit == "" {
			unit = u
		}
		if service == "" {
			service = s
		}
	}
	var actions []string
	// Remove pinned LSM links first: leaving them behind would keep enforcing
	// a policy with no agent to update or report it.
	if n, err := enforcer.DetachPinned(); err != nil {
		actions = append(actions, fmt.Sprintf("detach pinned LSM links: %v", err))
	} else if n > 0 {
		actions = append(actions, fmt.Sprintf("detached %d pinned LSM links", n))
	}
	if _, err := os.Stat(unit); err == nil {
		if out, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", service).CombinedOutput(); err != nil {
			actions = append(actions, fmt.Sprintf("systemctl disable --now %s: %v (%s)", service, err, string(out)))
		} else {
			actions = append(actions, "service stopped: "+service)
		}
		if err := os.Remove(unit); err == nil {
			actions = append(actions, "unit removed: "+unit)
		}
	}
	if opts.BinaryPath != "" {
		if err := os.Remove(opts.BinaryPath); err == nil {
			actions = append(actions, "binary removed: "+opts.BinaryPath)
		}
	}
	if opts.StateDir != "" {
		if err := os.RemoveAll(opts.StateDir); err == nil {
			actions = append(actions, "state removed: "+opts.StateDir)
		}
	}
	return actions, nil
}

// SpawnDetached schedules the removal after this process exits. Used when the
// agent runs as a service and would otherwise kill itself in the middle of the
// cleanup (systemctl stop terminates the caller).
func SpawnDetached(opts Options) error {
	unit, service := opts.UnitPath, opts.ServiceName
	if unit == "" || service == "" {
		u, s := DefaultSystemTargets()
		if unit == "" {
			unit = u
		}
		if service == "" {
			service = s
		}
	}
	script := fmt.Sprintf(`#!/bin/sh
sleep 3
systemctl disable --now %s >/dev/null 2>&1
rm -f %s
rm -f %s
rm -rf %s
`, service, unit, opts.BinaryPath, opts.StateDir)
	path := fmt.Sprintf("/tmp/tamperguard-uninstall-%d.sh", time.Now().UnixNano())
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return err
	}
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("setsid %s >/dev/null 2>&1 &", path))
	return cmd.Start()
}
