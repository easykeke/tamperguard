package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/fsverity"
	"github.com/easykeke/tamperguard/internal/store"
)

// deliverPending installs pull-mode releases addressed to this node.
//
// The publisher only staged the files on the control plane; this node fetches
// them, verifies every hash against the signed-off manifest and writes them
// under its own grant. The publisher therefore never needs network access to
// the protected host.
func (a *Agent) deliverPending(ctx context.Context) {
	if a.state.Role != "protect" {
		return
	}
	reqs, err := a.client.PendingDeliveries(ctx)
	if err != nil {
		a.log.Warn("list deliveries failed", "err", err)
		return
	}
	for _, req := range reqs {
		a.deliverOne(ctx, req)
	}
}

func (a *Agent) deliverOne(ctx context.Context, req store.PublishRequest) {
	info, err := a.client.DeliveryInfo(ctx, req.ID)
	if err != nil {
		a.log.Warn("delivery info failed", "request", req.ID, "err", err)
		return
	}
	if err := verifyManifestDigest(info.Manifest, info.Files); err != nil {
		_ = a.client.CompleteDelivery(ctx, req.ID, false, err.Error())
		a.record(audit.KindPublishFailed, "", "pull delivery rejected: "+err.Error())
		return
	}
	root, err := filepath.Abs(info.TargetDir)
	if err != nil {
		_ = a.client.CompleteDelivery(ctx, req.ID, false, err.Error())
		return
	}
	written := 0
	for _, f := range info.Files {
		if err := a.writeDeliveredFile(ctx, req.ID, f, root); err != nil {
			a.log.Error("pull delivery failed", "request", req.ID, "file", f.Path, "err", err)
			_ = a.client.CompleteDelivery(ctx, req.ID, false, err.Error())
			a.record(audit.KindPublishFailed, f.Path, "pull delivery failed: "+err.Error())
			return
		}
		written++
	}
	if a.opts.Verity {
		a.enableVerity(root, info.Files)
	}
	_ = a.client.CompleteDelivery(ctx, req.ID, true, "")
	a.record(audit.KindPublishDone, "", fmt.Sprintf("pull delivery %s: %d files", req.ID, written))
	a.log.Info("pull delivery installed", "request", req.ID, "files", written)
}

// enableVerity hardens the files just delivered: fs-verity makes them read-only
// and verifies every read against a Merkle tree. Best effort: unsupported
// filesystems log one warning and the kernel enforcer still protects the tree.
func (a *Agent) enableVerity(root string, files []store.PublishFile) {
	for _, f := range files {
		rel, ok := cleanRelPath(f.Path)
		if !ok {
			continue
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := fsverity.Enable(dst); err != nil {
			a.log.Warn("fs-verity not applied; release remains protected by the kernel enforcer",
				"file", dst, "err", err)
			a.record(audit.KindEnforcerError, dst, "fs-verity: "+err.Error())
			return
		}
	}
	a.log.Info("pull delivery hardened with fs-verity", "files", len(files))
}

// writeDeliveredFile retries on EPERM while the grant propagates to the kernel.
func (a *Agent) writeDeliveredFile(ctx context.Context, requestID string, f store.PublishFile, root string) error {
	rel, ok := cleanRelPath(f.Path)
	if !ok {
		return fmt.Errorf("invalid path %q", f.Path)
	}
	dst := filepath.Join(root, filepath.FromSlash(rel))
	if check, err := filepath.Rel(root, dst); err != nil || check == ".." || strings.HasPrefix(check, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes target directory", f.Path)
	}
	var lastErr error
	for attempt := 0; attempt < 15; attempt++ {
		lastErr = a.downloadAndWrite(ctx, requestID, rel, f, dst)
		if lastErr == nil {
			return nil
		}
		if !isPermissionError(lastErr) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return lastErr
}

func (a *Agent) downloadAndWrite(ctx context.Context, requestID, rel string, f store.PublishFile, dst string) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tg-deliver-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	h := sha256.New()
	n, err := a.client.DownloadArtifact(ctx, requestID, rel, io.MultiWriter(tmp, h))
	if cerr := tmp.Sync(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != f.Size {
		return fmt.Errorf("size mismatch for %s (got %d want %d)", rel, n, f.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("hash mismatch for %s", rel)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, dst)
}

// verifyManifestDigest recomputes the release digest the same way the publisher
// did, so a control plane that serves different bytes cannot go unnoticed.
func verifyManifestDigest(manifest string, files []store.PublishFile) error {
	if manifest == "" {
		return errors.New("manifest digest missing")
	}
	sorted := append([]store.PublishFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(h, "%s\t%s\n", f.Path, f.SHA256)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != manifest {
		return fmt.Errorf("manifest digest mismatch (got %s want %s)", got, manifest)
	}
	return nil
}

func cleanRelPath(p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return "", false
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
