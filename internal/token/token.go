// Package token implements short-lived, signed write authorisations
// ("release tokens") handed to a publishing agent.
//
// A token answers exactly three questions at the enforcement point:
//
//  1. who may write  (Subject: a publishing agent identity)
//  2. where          (Paths: absolute path prefixes)
//  3. until when     (ExpiresAt; TTL is capped by MaxTTL)
//
// It deliberately does NOT prove that the content being written is the
// content that was approved -- that is the caller's job via Manifest, the
// digest of the release manifest. Both checks must pass before a write is
// allowed; a valid token with a mismatched manifest is still a rejection.
//
// Wire format (compact, URL-safe, dependency free):
//
//	tg1.<base64url(payload JSON)>.<base64url(ed25519 signature)>
//
// The signature is computed over the literal ASCII "tg1.<payload>", so the
// version prefix is authenticated and cannot be downgraded or swapped.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	// prefix is part of the signed message; changing it invalidates old tokens.
	prefix = "tg1"

	// MaxTTL is the hard upper bound for a token lifetime. Anything longer is
	// rejected at verification time, regardless of what the issuer intended.
	MaxTTL = 15 * time.Minute

	// ClockSkew is tolerated on both sides of the validity window.
	ClockSkew = 30 * time.Second

	// Audience is the only accepted audience value.
	Audience = "tg-agent"
)

var (
	ErrMalformed         = errors.New("token: malformed")
	ErrBadSignature      = errors.New("token: signature verification failed")
	ErrExpired           = errors.New("token: expired")
	ErrNotYetValid       = errors.New("token: not yet valid")
	ErrAudience          = errors.New("token: wrong audience")
	ErrTTLTooLong        = errors.New("token: ttl exceeds maximum")
	ErrMalformedClaim    = errors.New("token: invalid claim")
	ErrPathNotAuthorised = errors.New("token: path not authorised")
)

var b64 = base64.RawURLEncoding

// Claims is the signed payload. Field names are part of the wire format;
// changing one breaks every outstanding token and every verifier, so treat
// this struct as frozen once released.
type Claims struct {
	Version   int      `json:"v"`
	TokenID   string   `json:"jti"`
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	NodeID    string   `json:"node"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	Paths     []string `json:"paths"`
	Manifest  string   `json:"manifest,omitempty"`
	PolicyRev string   `json:"policy_rev,omitempty"`
}

// GenerateKey returns a fresh Ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("token: generate key: %w", err)
	}
	return pub, priv, nil
}

// Sign validates the claim shape and returns the compact wire format.
// Time-dependent checks are intentionally NOT applied here so that a token
// can be prepared slightly ahead of its NotBefore.
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: bad private key length", ErrMalformedClaim)
	}
	if err := c.validateShape(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("token: marshal claims: %w", err)
	}
	msg := prefix + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(msg))
	return msg + "." + b64.EncodeToString(sig), nil
}

// Parse decodes a token WITHOUT verifying its signature. Use Verify for any
// decision that matters.
func Parse(raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return nil, ErrMalformed
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrMalformed)
	}
	var c Claims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: bad payload json", ErrMalformed)
	}
	return &c, nil
}

// Verify checks the signature first, then shape, then the validity window.
// A caller must additionally check revocation and node binding.
func Verify(pub ed25519.PublicKey, raw string, now time.Time) (*Claims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: bad public key length", ErrBadSignature)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return nil, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrMalformed)
	}
	msg := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return nil, ErrBadSignature
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := c.validateShape(); err != nil {
		return nil, err
	}
	if err := c.validateWindow(now); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Claims) validateShape() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: unsupported version %d", ErrMalformedClaim, c.Version)
	}
	if c.TokenID == "" || c.Subject == "" || c.NodeID == "" || c.Issuer == "" {
		return fmt.Errorf("%w: missing identity field", ErrMalformedClaim)
	}
	if c.Audience != Audience {
		return ErrAudience
	}
	if len(c.Paths) == 0 {
		return fmt.Errorf("%w: no paths authorised", ErrMalformedClaim)
	}
	for _, p := range c.Paths {
		if _, ok := NormalizePath(p); !ok {
			return fmt.Errorf("%w: path %q is not absolute and clean", ErrMalformedClaim, p)
		}
	}
	if c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("%w: exp <= iat", ErrMalformedClaim)
	}
	if c.ExpiresAt-c.IssuedAt > int64(MaxTTL/time.Second) {
		return ErrTTLTooLong
	}
	return nil
}

func (c *Claims) validateWindow(now time.Time) error {
	n := now.Unix()
	if n > c.ExpiresAt+int64(ClockSkew/time.Second) {
		return ErrExpired
	}
	if n < c.NotBefore-int64(ClockSkew/time.Second) {
		return ErrNotYetValid
	}
	return nil
}

// Covers reports whether the token authorises writes below target.
// The target must be an absolute clean path; matching is component-aware so
// "/var/www/html-evil" is not covered by "/var/www/html".
func (c *Claims) Covers(target string) bool {
	tp, ok := NormalizePath(target)
	if !ok {
		return false
	}
	for _, p := range c.Paths {
		if PathCovered(p, tp) {
			return true
		}
	}
	return false
}

// CheckManifest verifies that the digest of the content about to be written
// matches the digest bound into the token. An empty expected digest is only
// allowed when the token carries no Manifest (path-only token, weaker mode).
func (c *Claims) CheckManifest(actualDigest string) error {
	if c.Manifest == "" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(c.Manifest), strings.TrimSpace(actualDigest)) {
		return fmt.Errorf("%w: manifest digest mismatch", ErrMalformedClaim)
	}
	return nil
}

// NormalizePath returns the canonical absolute form of p, or false if p is
// not an absolute path, contains a traversal element, or is not clean.
//
// Two families are accepted and kept in a single canonical spelling:
//
//	Unix      "/var/www/site"        (kept as is)
//	Windows   `C:\inetpub\wwwroot`   -> "C:/inetpub/wwwroot"
//	          `\\server\share\dir`   -> "//server/share/dir"
//
// Windows paths are stored with forward slashes so that the policy, token and
// enforcement layers share one representation regardless of the host the
// control plane runs on.
func NormalizePath(p string) (string, bool) {
	if p == "" || strings.Contains(p, "\x00") {
		return "", false
	}
	if strings.HasPrefix(p, "/") {
		if strings.HasPrefix(p, "//") {
			return normalizeUNC(p)
		}
		if hasTraversal(p, "/") {
			return "", false
		}
		return path.Clean(p), true
	}
	if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return "", false
	}
	q := strings.ReplaceAll(p, "\\", "/")
	if hasTraversal(q, "/") {
		return "", false
	}
	c := path.Clean(q)
	if len(c) == 2 && c[1] == ':' {
		c += "/"
	}
	return strings.ToUpper(c[:1]) + c[1:], true
}

func normalizeUNC(p string) (string, bool) {
	q := strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(q, "/")
	var kept []string
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return "", false
		}
		kept = append(kept, seg)
	}
	if len(kept) < 2 {
		return "", false
	}
	return "//" + strings.Join(kept, "/"), true
}

func hasTraversal(p, sep string) bool {
	for _, seg := range strings.Split(p, sep) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isWindowsCanonical reports whether a normalized path uses Windows spelling.
func isWindowsCanonical(p string) bool {
	if strings.HasPrefix(p, "//") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && isASCIILetter(p[0])
}

// PathCovered reports whether target equals base or lives below it. Windows
// paths are compared case-insensitively because the filesystem is.
func PathCovered(base, target string) bool {
	b, ok := NormalizePath(base)
	if !ok {
		return false
	}
	t, ok := NormalizePath(target)
	if !ok {
		return false
	}
	if isWindowsCanonical(b) || isWindowsCanonical(t) {
		b = strings.ToLower(b)
		t = strings.ToLower(t)
	}
	if b == "/" || b == "//" {
		return true
	}
	if len(b) >= 3 && b[1] == ':' && b[2:] == "/" {
		// drive root: C:/ covers everything on C:
		return t == b || strings.HasPrefix(t, b)
	}
	return t == b || strings.HasPrefix(t, b+"/")
}

// DigestString returns the hex SHA-256 of s, used for manifest digests.
func DigestString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
