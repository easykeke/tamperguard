//go:build !linux && !windows

package uninstall

import (
	"context"
	"fmt"
	"os"
)

// DefaultSystemTargets has no meaning on this platform.
func DefaultSystemTargets() (unitPath, serviceName string) { return "", "" }

// Perform removes the state directory and binary on platforms without a service
// manager integration.
func Perform(ctx context.Context, opts Options) ([]string, error) {
	if opts.DryRun {
		return []string{"dry-run: would remove " + opts.StateDir}, nil
	}
	var actions []string
	if opts.BinaryPath != "" {
		if err := os.Remove(opts.BinaryPath); err == nil {
			actions = append(actions, "binary removed: "+opts.BinaryPath)
		}
	}
	if opts.StateDir != "" {
		if err := os.RemoveAll(opts.StateDir); err == nil {
			actions = append(actions, "state removed: "+opts.StateDir)
		} else {
			return actions, fmt.Errorf("remove state: %w", err)
		}
	}
	return actions, nil
}

// SpawnDetached falls back to a direct removal.
func SpawnDetached(opts Options) error {
	_, err := Perform(context.Background(), opts)
	return err
}
