//go:build windows

package enforcer

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/baseline"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/watch"
)

// Windows self-heal: the ACL/MIC layers stop ordinary writes, but an
// administrator can still take ownership and rewrite a file. Without a kernel
// driver we cannot block that, so the backend keeps a content-addressed baseline
// of every protected file and reconciles the tree on a timer:
//
//   - a modified/deleted file is restored from the baseline;
//   - a file that did not exist in the baseline is removed;
//   - each repair becomes a tamper.restored audit record.
//
// A release window is treated as trusted: changes made while a grant is live
// are not reverted, and when the grant ends the tree becomes the new baseline.
// The loop runs as the agent (SYSTEM), which can write files that carry the
// System integrity label.

// setupSelfHeal opens the baseline store and starts the reconciliation loop.
func (w *WindowsACL) setupSelfHeal(stateDir string) error {
	if stateDir == "" {
		return nil
	}
	base, err := baseline.Open(filepath.Join(stateDir, "baseline"))
	if err != nil {
		return err
	}
	w.base = base
	w.scanSignal = make(chan struct{}, 1)
	w.scanInterval = 30 * time.Second
	if raw := os.Getenv("TG_WIN_SCAN_SECONDS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 2 {
			w.scanInterval = time.Duration(n) * time.Second
		}
	}
	go w.healLoop()
	return nil
}

func (w *WindowsACL) healLoop() {
	t := time.NewTicker(w.scanInterval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.healOnce()
		case <-w.scanSignal:
			// Coalesce bursts: a release writes many files, a single scan
			// reconciles all of them.
			time.Sleep(300 * time.Millisecond)
			select {
			case <-w.scanSignal:
			default:
			}
			w.healOnce()
		}
	}
}

// restartWatchers re-arms ReadDirectoryChangesW on the protected roots so a
// tamper attempt triggers an immediate scan instead of waiting for the ticker.
func (w *WindowsACL) restartWatchers(roots []string) {
	w.watchMu.Lock()
	defer w.watchMu.Unlock()
	for _, wv := range w.watchers {
		_ = wv.Close()
	}
	w.watchers = nil
	for _, root := range roots {
		wv, err := watch.Watch(root, func() {
			select {
			case w.scanSignal <- struct{}{}:
			default:
			}
		})
		if err != nil {
			w.log.Warn("windows-acl: directory watcher failed", "root", root, "err", err)
			continue
		}
		w.watchers = append(w.watchers, wv)
	}
}

// baselineRoots returns the native paths of every enforce-mode directory.
func (w *WindowsACL) baselineRoots(rt Runtime) []string {
	if rt.Policy == nil {
		return nil
	}
	var roots []string
	for _, rule := range rt.Policy.Policy.Paths {
		if rule.Mode != policy.ModeEnforce {
			continue
		}
		norm, ok := normalizeRulePath(rule.Path)
		if !ok {
			continue
		}
		native := nativePath(norm)
		if st, err := os.Stat(native); err == nil && st.IsDir() {
			roots = append(roots, native)
		}
	}
	return roots
}

// maybeSnapshot (re)snapshots the baseline. It never snapshots while a release
// grant is live, so a publisher's writes are not recorded as tampering.
func (w *WindowsACL) maybeSnapshot(rt Runtime, now int64) {
	grantActive := false
	for _, g := range rt.Grants {
		if g.ExpiresAt == 0 || g.ExpiresAt > now {
			for _, p := range g.Paths {
				if _, ok := normalizeRulePath(p); ok {
					grantActive = true
					break
				}
			}
		}
		if grantActive {
			break
		}
	}

	w.mu.Lock()
	if grantActive {
		w.needResnapshot = true
		w.mu.Unlock()
		return
	}
	digest := ""
	if rt.Policy != nil {
		digest = rt.Policy.Digest
	}
	if w.snapshotted && !w.needResnapshot && digest == w.policyDigest {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()

	roots := w.baselineRoots(rt)
	if len(roots) == 0 {
		return
	}
	if err := w.base.Snapshot(roots); err != nil {
		w.log.Warn("windows-acl: baseline snapshot failed", "err", err)
		return
	}
	w.mu.Lock()
	w.snapshotted = true
	w.needResnapshot = false
	w.policyDigest = digest
	w.mu.Unlock()
	w.restartWatchers(roots)
	w.log.Info("windows-acl: self-heal baseline ready", "files", w.base.Len())
}

func (w *WindowsACL) grantActive(rt Runtime, nativePath string, now int64) bool {
	norm, ok := normalizeRulePath(normFromNative(nativePath))
	if !ok {
		return false
	}
	return w.grantCovers(rt, norm, now)
}

func (w *WindowsACL) recentlyHealed(path string) bool {
	w.healMu.Lock()
	defer w.healMu.Unlock()
	ts, ok := w.recent[path]
	return ok && time.Since(time.Unix(0, ts)) < 5*time.Second
}

func (w *WindowsACL) markHealed(path string) {
	w.healMu.Lock()
	defer w.healMu.Unlock()
	if w.recent == nil {
		w.recent = map[string]int64{}
	}
	w.recent[path] = time.Now().UnixNano()
}

// healOnce reconciles the protected tree with the baseline.
func (w *WindowsACL) healOnce() {
	w.mu.Lock()
	rt := w.rt
	snapshotted := w.snapshotted
	base := w.base
	w.mu.Unlock()
	if base == nil || !snapshotted || rt.Policy == nil {
		return
	}
	now := time.Now().Unix()

	for _, e := range base.List() {
		if e.IsDir {
			if _, err := os.Lstat(e.Path); err != nil {
				_ = os.MkdirAll(e.Path, os.FileMode(e.Mode))
			}
			continue
		}
		if w.grantActive(rt, e.Path, now) || w.recentlyHealed(e.Path) {
			continue
		}
		data, err := os.ReadFile(e.Path)
		changed := err != nil
		if !changed {
			sum := sha256.Sum256(data)
			changed = hex.EncodeToString(sum[:]) != e.SHA256
		}
		if !changed {
			continue
		}
		w.log.Warn("windows-acl: tampering detected, restoring from baseline", "path", e.Path)
		if rerr := base.RestoreTree(e.Path); rerr != nil {
			w.log.Error("windows-acl: restore failed", "path", e.Path, "err", rerr)
			continue
		}
		w.markHealed(e.Path)
		w.events.Emit(Event{
			Time: now, Kind: audit.KindTamperRestored, Path: e.Path,
			Op:      policy.OpOpenWrite,
			Subject: policy.Subject{ExePath: "selfheal"},
			Reason:  "windows-selfheal",
		})
	}

	// Remove files that appeared after the baseline was taken.
	for _, root := range w.baselineRoots(rt) {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if _, ok := base.Get(p); ok || w.grantActive(rt, p, now) || w.recentlyHealed(p) {
				return nil
			}
			if rerr := os.Remove(p); rerr == nil {
				w.markHealed(p)
				w.events.Emit(Event{
					Time: now, Kind: audit.KindTamperRestored, Path: p,
					Op:      policy.OpUnlink,
					Subject: policy.Subject{ExePath: "selfheal"},
					Reason:  "windows-selfheal-untracked",
				})
			}
			return nil
		})
	}
}
