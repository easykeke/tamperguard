// Package baseline stores the last-known-good copy of every protected file and
// restores it when the degraded enforcer (fanotify) sees an unauthorised write.
//
// Storage layout under root:
//
//	index.json          map of absolute path -> entry
//	blobs/<sha256>.blob file contents, content addressed
//
// The baseline is a recovery mechanism, not a backup product: it keeps one
// version per path, and only files that existed when the snapshot was taken.
// Files created later have no entry, so a restore of such a path deletes it.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry describes one protected path at snapshot time.
type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mode   uint32 `json:"mode"`
	IsDir  bool   `json:"is_dir,omitempty"`
}

// Manager owns the baseline on disk and its in-memory index.
type Manager struct {
	root string

	mu       sync.RWMutex
	entries  map[string]Entry
	dirty    bool
	lastSave time.Time
}

const (
	indexFile = "index.json"
	blobDir   = "blobs"
)

// Open loads (or creates) a baseline manager rooted at dir.
func Open(dir string) (*Manager, error) {
	if err := os.MkdirAll(filepath.Join(dir, blobDir), 0o700); err != nil {
		return nil, fmt.Errorf("baseline: create root: %w", err)
	}
	m := &Manager{root: dir, entries: map[string]Entry{}}
	raw, err := os.ReadFile(filepath.Join(dir, indexFile))
	if err == nil {
		var list []Entry
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("baseline: parse index: %w", err)
		}
		for _, e := range list {
			m.entries[e.Path] = e
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

// Len returns the number of indexed paths.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// Snapshot replaces the baseline with the current content of the given roots.
func (m *Manager) Snapshot(roots []string) error {
	next := map[string]Entry{}
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		info, err := os.Lstat(abs)
		if err != nil {
			continue // a protected path that does not exist yet is not an error
		}
		if !info.IsDir() {
			if e, ok := m.snapshotFile(abs, info); ok {
				next[abs] = e
			}
			continue
		}
		next[abs] = Entry{Path: abs, IsDir: true, Mode: uint32(info.Mode().Perm())}
		err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable subtree: keep what we have
			}
			if p == abs {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			if fi.IsDir() {
				next[p] = Entry{Path: p, IsDir: true, Mode: uint32(fi.Mode().Perm())}
				return nil
			}
			if !fi.Mode().IsRegular() {
				return nil // sockets, symlinks, devices are not snapshotted
			}
			if e, ok := m.snapshotFile(p, fi); ok {
				next[p] = e
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.entries = next
	m.dirty = true
	m.mu.Unlock()
	m.flush(true)
	return nil
}

func (m *Manager) snapshotFile(path string, info os.FileInfo) (Entry, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, false
	}
	sum := sha256.Sum256(data)
	blob := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(m.root, blobDir, blob+".blob"), data, 0o600); err != nil {
		return Entry{}, false
	}
	return Entry{Path: path, SHA256: blob, Size: int64(len(data)), Mode: uint32(info.Mode().Perm())}, true
}

// Take re-reads one path and makes its current content the new baseline. Used
// when an authorised writer changes a file.
func (m *Manager) Take(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		m.Remove(path)
		return
	}
	var e Entry
	if info.IsDir() {
		e = Entry{Path: path, IsDir: true, Mode: uint32(info.Mode().Perm())}
	} else if info.Mode().IsRegular() {
		var ok bool
		e, ok = m.snapshotFile(path, info)
		if !ok {
			return
		}
	} else {
		return
	}
	m.mu.Lock()
	m.entries[path] = e
	m.dirty = true
	m.mu.Unlock()
	m.flush(false)
}

// Remove drops one path from the baseline.
func (m *Manager) Remove(path string) {
	m.mu.Lock()
	if _, ok := m.entries[path]; ok {
		delete(m.entries, path)
		m.dirty = true
	}
	m.mu.Unlock()
	m.flush(false)
}

// Get returns the baseline entry for path.
func (m *Manager) Get(path string) (Entry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[path]
	return e, ok
}

// List returns a copy of all baseline entries.
func (m *Manager) List() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e)
	}
	return out
}

// RestoreTree puts path (and anything below it) back to the baseline.
//
//   - indexed file: rewritten from the blob
//   - indexed directory: recreated, then its indexed children restored
//   - path that was never indexed (it was created after the snapshot): removed
func (m *Manager) RestoreTree(path string) error {
	m.mu.RLock()
	var affected []Entry
	for p, e := range m.entries {
		if p == path || strings.HasPrefix(p, path+string(os.PathSeparator)) {
			affected = append(affected, e)
		}
	}
	m.mu.RUnlock()

	if len(affected) == 0 {
		// Not in the baseline: it appeared after the snapshot, undo it.
		if _, err := os.Lstat(path); err != nil {
			return nil
		}
		return os.RemoveAll(path)
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].Path < affected[j].Path })
	for _, e := range affected {
		if e.IsDir {
			if err := os.MkdirAll(e.Path, os.FileMode(e.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := m.restoreFile(e); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) restoreFile(e Entry) error {
	data, err := os.ReadFile(filepath.Join(m.root, blobDir, e.SHA256+".blob"))
	if err != nil {
		return fmt.Errorf("baseline: blob for %s: %w", e.Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(e.Path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(e.Path), ".tg-restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Chmod(name, os.FileMode(e.Mode)); err != nil {
		return err
	}
	return os.Rename(name, e.Path)
}

// flush persists the index, at most once per second unless forced.
func (m *Manager) flush(force bool) {
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return
	}
	if !force && time.Since(m.lastSave) < time.Second {
		m.mu.Unlock()
		return
	}
	list := make([]Entry, 0, len(m.entries))
	for _, e := range m.entries {
		list = append(list, e)
	}
	m.dirty = false
	m.lastSave = time.Now()
	m.mu.Unlock()

	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	raw, err := json.Marshal(list)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(m.root, ".index-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return
	}
	tmp.Close()
	_ = os.Chmod(name, 0o600)
	_ = os.Rename(name, filepath.Join(m.root, indexFile))
}

// Close flushes the index.
func (m *Manager) Close() error {
	m.flush(true)
	return nil
}

// CopyBlob is a small helper used by tests to inspect stored content.
func (m *Manager) CopyBlob(sha string, w io.Writer) error {
	f, err := os.Open(filepath.Join(m.root, blobDir, sha+".blob"))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
