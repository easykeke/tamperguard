// Package webproxy implements the web-layer integrity proxy.
//
// A static site is snapshotted into a content-addressed store together with a
// manifest of path -> SHA-256. The proxy serves only manifest entries and
// re-verifies the on-disk file for every request: if it no longer matches, the
// trusted blob is served instead and a tamper event is recorded. Visitors get
// authentic content even when the document root has been modified (for example
// by an administrator who bypassed the file-level protection), and the mismatch
// stays visible in the audit trail.
package webproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry describes one file of the trusted site.
type Entry struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode,omitempty"`
	ModAt  int64  `json:"mtime,omitempty"`
}

// Manifest is the trusted snapshot of a site.
type Manifest struct {
	Version   int              `json:"version"`
	CreatedAt int64            `json:"created_at"`
	Root      string           `json:"root,omitempty"`
	Entries   map[string]Entry `json:"entries"`
}

// Lookup maps a request path to a manifest entry.
func (m *Manifest) Lookup(rel string) (Entry, bool) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		rel = "index.html"
	}
	if e, ok := m.Entries[rel]; ok {
		return e, true
	}
	// Directory request: /dir/ -> dir/index.html
	if strings.HasSuffix(rel, "/") {
		if e, ok := m.Entries[rel+"index.html"]; ok {
			return e, true
		}
	}
	return Entry{}, false
}

// blobDir is where the trusted copies live.
func BlobDir(state string) string { return filepath.Join(state, "blobs") }

// ManifestPath is the persisted manifest location.
func ManifestPath(state string) string { return filepath.Join(state, "manifest.json") }

// LoadManifest reads a previously written manifest.
func LoadManifest(state string) (*Manifest, error) {
	raw, err := os.ReadFile(ManifestPath(state))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Entries == nil {
		return nil, errors.New("webproxy: manifest has no entries")
	}
	return &m, nil
}

// SaveManifest writes the manifest atomically.
func SaveManifest(state string, m *Manifest) error {
	if err := os.MkdirAll(state, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := ManifestPath(state) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ManifestPath(state))
}

// Snapshot walks root, copies every regular file into the blob store and returns
// the manifest. Symlinks are rejected: following them would let a compromised
// tree pull content from outside the trusted directory.
func Snapshot(root, state string) (*Manifest, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(BlobDir(state), 0o750); err != nil {
		return nil, err
	}
	m := &Manifest{Version: 1, CreatedAt: time.Now().Unix(), Root: abs, Entries: map[string]Entry{}}
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("webproxy: refusing to follow symlink %s", p)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("webproxy: unsupported file type at %s", p)
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		sha := hex.EncodeToString(sum[:])
		blob := filepath.Join(BlobDir(state), sha)
		if _, statErr := os.Stat(blob); statErr != nil {
			if err := os.WriteFile(blob, data, 0o600); err != nil {
				return err
			}
		}
		info, _ := d.Info()
		var modAt int64
		var mode uint32
		if info != nil {
			modAt = info.ModTime().Unix()
			mode = uint32(info.Mode().Perm())
		}
		m.Entries[filepath.ToSlash(rel)] = Entry{SHA256: sha, Size: int64(len(data)), Mode: mode, ModAt: modAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(m.Entries) == 0 {
		return nil, errors.New("webproxy: site has no regular files")
	}
	if err := SaveManifest(state, m); err != nil {
		return nil, err
	}
	return m, nil
}

// EntryPaths returns the sorted manifest paths (useful for diagnostics).
func (m *Manifest) EntryPaths() []string {
	out := make([]string, 0, len(m.Entries))
	for p := range m.Entries {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// CleanRequestPath converts a URL path into a clean relative slash path.
func CleanRequestPath(urlPath string) (string, error) {
	if strings.Contains(urlPath, "\x00") {
		return "", errors.New("invalid path")
	}
	unescaped := urlPath
	if strings.Contains(unescaped, "\\") {
		return "", errors.New("invalid path")
	}
	// Reject traversal segments before Clean resolves them away.
	for _, seg := range strings.Split(unescaped, "/") {
		if seg == ".." {
			return "", errors.New("invalid path")
		}
	}
	cleaned := path.Clean("/" + unescaped)
	rel := strings.TrimPrefix(cleaned, "/")
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." {
			return "", errors.New("invalid path")
		}
	}
	if rel == "" {
		return "index.html", nil
	}
	// Keep the trailing slash so a directory request can resolve to its index.
	if strings.HasSuffix(unescaped, "/") {
		rel += "/"
	}
	return rel, nil
}
