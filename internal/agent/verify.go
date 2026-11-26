package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/easykeke/tamperguard/internal/digest"
	"github.com/easykeke/tamperguard/internal/store"
)

// verifyInstalled re-reads every installed file and returns the canonical
// release digest. This is the proof the publisher compares against its own.
func verifyInstalled(root string, files []store.PublishFile) (string, int, error) {
	out := make([]digest.File, 0, len(files))
	for _, f := range files {
		path := filepath.Join(root, filepath.FromSlash(f.Path))
		sum, err := sha256File(path)
		if err != nil {
			return "", 0, err
		}
		if sum != f.SHA256 {
			return "", 0, fmt.Errorf("%s: got %s, manifest says %s", f.Path, sum, f.SHA256)
		}
		out = append(out, digest.File{Path: f.Path, SHA256: sum})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return digest.OfFiles(out), len(out), nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
