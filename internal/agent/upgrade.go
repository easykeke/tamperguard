package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/easykeke/tamperguard/internal/config"
)

// ErrUpgradeStaged is returned by Run when a new binary has replaced the
// running one and the service manager should restart the process.
var ErrUpgradeStaged = errors.New("agent: upgrade staged, restart required")

// MaybeUpgrade checks for a signed update, verifies it and swaps the binary in.
// It returns true when the caller should exit so the service manager restarts.
func MaybeUpgrade(ctx context.Context, state *config.AgentState, client *Client, log *slog.Logger, current string) (bool, error) {
	if state.ReleasePub == "" {
		return false, errors.New("agent: no release public key in state; re-enrol to enable upgrades")
	}
	pub, err := parsePublicKeyHex(state.ReleasePub)
	if err != nil {
		return false, fmt.Errorf("agent: release key unusable: %w", err)
	}
	info, err := client.UpgradeInfo(ctx, current, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return false, err
	}
	if !info.Available || info.Manifest.Version == current {
		return false, nil
	}
	m := info.Manifest
	if err := m.Verify(pub); err != nil {
		return false, fmt.Errorf("agent: upgrade manifest rejected: %w", err)
	}

	dir := filepath.Join(state.StateDir, "upgrade")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	tmp := filepath.Join(dir, "tg-agent-"+m.Version+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	n, err := client.DownloadUpgrade(ctx, m, io.MultiWriter(f, h))
	if cerr := f.Sync(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("agent: download upgrade: %w", err)
	}
	if n != m.Size {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("agent: upgrade size mismatch (got %d, want %d)", n, m.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("agent: upgrade hash mismatch (got %s)", got)
	}

	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if err := swapBinary(exe, tmp); err != nil {
		return false, fmt.Errorf("agent: swap binary: %w", err)
	}
	log.Info("agent binary upgraded", "version", m.Version, "binary", exe)
	return true, nil
}

// swapBinary atomically replaces exe with src. If the two live on different
// filesystems the artefact is copied next to the target first, so the final
// step is always a rename within one directory.
func swapBinary(exe, src string) error {
	if err := os.Rename(src, exe); err == nil {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".tg-upgrade-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	in, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return err
	}
	defer in.Close()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	if err := os.Rename(name, exe); err != nil {
		return err
	}
	return os.Remove(src)
}
