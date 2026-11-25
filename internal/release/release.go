// Package release defines the signed manifest that authorises an agent binary
// to replace itself.
//
// The manifest is deliberately tiny and canonical: the signature covers a
// single string built from every field, so there is no JSON serialisation
// ambiguity between the signer and the verifier.
package release

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ManifestPrefix domain-separates release signatures from token and policy
// signatures that use the same key material in other deployments.
const ManifestPrefix = "tg-release-v1"

var (
	// ErrBadSignature means the manifest was not signed by the release key.
	ErrBadSignature = errors.New("release: invalid signature")
	// ErrBadManifest means required fields are missing or malformed.
	ErrBadManifest = errors.New("release: malformed manifest")
	// ErrVersion means the version string is not acceptable as a path element.
	ErrVersion = errors.New("release: invalid version")
)

var versionRe = regexp.MustCompile(`^[0-9A-Za-z._-]{1,64}$`)

// Manifest is one published agent build.
type Manifest struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature,omitempty"`
}

// Encode returns the canonical signed string.
func (m Manifest) Encode() string {
	return fmt.Sprintf("%s:%s:%s/%s:%s:%d", ManifestPrefix, m.Version, m.OS, m.Arch, m.SHA256, m.Size)
}

// Validate checks the fields the signature and download depend on.
func (m Manifest) Validate() error {
	if !versionRe.MatchString(m.Version) {
		return ErrVersion
	}
	if m.OS == "" || m.Arch == "" {
		return fmt.Errorf("%w: os/arch required", ErrBadManifest)
	}
	if len(m.SHA256) != 64 {
		return fmt.Errorf("%w: sha256 must be 64 hex chars", ErrBadManifest)
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return fmt.Errorf("%w: sha256 is not hex", ErrBadManifest)
	}
	if m.Size <= 0 {
		return fmt.Errorf("%w: size must be positive", ErrBadManifest)
	}
	return nil
}

// Sign fills in Signature.
func (m *Manifest) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return ErrBadSignature
	}
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(m.Encode())))
	return nil
}

// Verify checks the signature and the field shape.
func (m Manifest) Verify(pub ed25519.PublicKey) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	sig, err := hex.DecodeString(strings.TrimSpace(m.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, []byte(m.Encode()), sig) {
		return ErrBadSignature
	}
	return nil
}
