// Package digest computes the canonical release digest that both the publisher
// and the target agent use, so the publisher can prove the target's file hashes
// match what it sent.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// File is one path/hash pair.
type File struct {
	Path   string
	SHA256 string
}

// OfFiles returns the same value publish.Manifest.Digest produces:
// sha256 over "path\tsha256\n" in the given order.
func OfFiles(files []File) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\t%s\n", f.Path, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}
