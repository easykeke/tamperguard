// Package selfcheck keeps a hash baseline of the agent's own files.
//
// It does not replace kernel enforcement: a root user can still stop the agent
// or edit the binary. What it does is make silent modification visible — the
// agent compares its binary, service unit and config against the baseline on
// startup and periodically, and appends an `agent.selfcheck_failed` record to
// the signed audit chain when anything changed.
package selfcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// File is one hashed file.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the stored baseline.
type Manifest struct {
	Version   int    `json:"version"`
	CreatedAt int64  `json:"created_at"`
	Files     []File `json:"files"`
}

// Diff describes one changed file.
type Diff struct {
	Path     string
	Expected string
	Got      string
	Missing  bool
}

// Build hashes every existing path.
func Build(paths []string) (*Manifest, error) {
	m := &Manifest{Version: 1, CreatedAt: time.Now().Unix()}
	for _, p := range paths {
		if p == "" {
			continue
		}
		f, err := hashFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		m.Files = append(m.Files, f)
	}
	if len(m.Files) == 0 {
		return nil, errors.New("selfcheck: no files to hash")
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m, nil
}

func hashFile(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return File{}, err
	}
	return File{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

// Save writes the baseline atomically.
func Save(path string, m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads a baseline.
func Load(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Compare reports files whose hash no longer matches (or disappeared).
func Compare(m *Manifest) ([]Diff, error) {
	var diffs []Diff
	for _, want := range m.Files {
		got, err := hashFile(want.Path)
		if errors.Is(err, os.ErrNotExist) {
			diffs = append(diffs, Diff{Path: want.Path, Expected: want.SHA256, Missing: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		if got.SHA256 != want.SHA256 {
			diffs = append(diffs, Diff{Path: want.Path, Expected: want.SHA256, Got: got.SHA256})
		}
	}
	return diffs, nil
}

// String formats a diff for an audit detail.
func (d Diff) String() string {
	if d.Missing {
		return fmt.Sprintf("%s: missing (expected %s)", d.Path, short(d.Expected))
	}
	return fmt.Sprintf("%s: %s != %s", d.Path, short(d.Got), short(d.Expected))
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
