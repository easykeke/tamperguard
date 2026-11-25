// Package idgen produces opaque identifiers. IDs are random rather than
// sequential so that they do not leak enumeration order or counts.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns prefix followed by 8 random bytes (16 hex chars).
func New(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the host is in a state where security
		// decisions must not be made; panic is the honest outcome.
		panic("idgen: crypto/rand unavailable: " + err.Error())
	}
	return prefix + hex.EncodeToString(b)
}

// Token returns a URL-safe random secret with n bytes of entropy.
func Token(n int) string {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("idgen: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
