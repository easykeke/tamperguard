package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SiteFile is one file of a published static site, as the control plane knows it.
type SiteFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SiteManifest is the control-plane-signed description of the site a node should
// be serving. It binds the node, the publish request, the release digest and the
// target directory to a sorted file list.
type SiteManifest struct {
	NodeID    string     `json:"node_id"`
	RequestID string     `json:"request_id"`
	Manifest  string     `json:"manifest"` // release manifest digest
	TargetDir string     `json:"target_dir"`
	Files     []SiteFile `json:"files"`
	SignedAt  int64      `json:"signed_at"`
	Signature string     `json:"signature,omitempty"`
}

const siteManifestVersion = "tg-site-manifest-v1"

// sortFiles orders files by path so the canonical form is deterministic.
func (m *SiteManifest) sortFiles() {
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
}

// Canonical returns the byte string covered by the signature. It includes the
// version marker so a signature cannot be replayed as a different structure.
func (m *SiteManifest) Canonical() []byte {
	m.sortFiles()
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\nnode=%s\nrequest=%s\nmanifest=%s\ntarget=%s\nsigned_at=%d\n", siteManifestVersion, m.NodeID, m.RequestID, m.Manifest, m.TargetDir, m.SignedAt)
	for _, f := range m.Files {
		fmt.Fprintf(&b, "file=%s\tsha256=%s\tsize=%d\n", f.Path, f.SHA256, f.Size)
	}
	return b.Bytes()
}

// SignSiteManifest fills SignedAt and Signature.
func SignSiteManifest(priv ed25519.PrivateKey, m *SiteManifest) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("release: invalid signing key")
	}
	if m.NodeID == "" || m.RequestID == "" || m.Manifest == "" || len(m.Files) == 0 {
		return errors.New("release: incomplete site manifest")
	}
	m.SignedAt = time.Now().Unix()
	m.sortFiles()
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m.Canonical()))
	return nil
}

// VerifySiteManifest checks the signature and basic shape.
func VerifySiteManifest(pub ed25519.PublicKey, m *SiteManifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("release: invalid public key")
	}
	if m.Signature == "" {
		return errors.New("release: site manifest is not signed")
	}
	if m.NodeID == "" || m.RequestID == "" || m.Manifest == "" || len(m.Files) == 0 {
		return errors.New("release: incomplete site manifest")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("release: signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, m.Canonical(), sig) {
		return errors.New("release: site manifest signature does not verify")
	}
	return nil
}

// ValidSHA256 reports whether s looks like a hex SHA-256.
func ValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
