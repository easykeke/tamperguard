package token

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func baseClaims(now time.Time) Claims {
	return Claims{
		Version:   1,
		TokenID:   "tok-1",
		Issuer:    "tg-server",
		Subject:   "publisher-1",
		NodeID:    "node-1",
		Audience:  Audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Paths:     []string{"/var/www/site"},
		Manifest:  "deadbeef",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := Sign(priv, baseClaims(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(pub, raw, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.TokenID != "tok-1" || got.Subject != "publisher-1" {
		t.Fatalf("claims not preserved: %+v", got)
	}
	if !got.Covers("/var/www/site/index.html") {
		t.Fatal("expected path to be covered")
	}
	if got.Covers("/var/www/site-evil/index.html") {
		t.Fatal("prefix matching must be component aware")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv, _ := GenerateKey()
	now := time.Now()
	raw, _ := Sign(priv, baseClaims(now))
	parts := strings.Split(raw, ".")

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	c.Paths = []string{"/var/www/other"}
	evil, _ := json.Marshal(c)
	tampered := parts[0] + "." + b64.EncodeToString(evil) + "." + parts[2]

	if _, err := Verify(pub, tampered, now); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv, _ := GenerateKey()
	now := time.Now()
	raw, _ := Sign(priv, baseClaims(now))
	if _, err := Verify(pub, raw, now.Add(10*time.Minute)); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	pub, priv, _ := GenerateKey()
	now := time.Now()
	raw, _ := Sign(priv, baseClaims(now.Add(2*time.Minute)))
	if _, err := Verify(pub, raw, now); err != ErrNotYetValid {
		t.Fatalf("want ErrNotYetValid, got %v", err)
	}
}

func TestSignRejectsOverlongTTL(t *testing.T) {
	_, priv, _ := GenerateKey()
	now := time.Now()
	c := baseClaims(now)
	c.ExpiresAt = now.Add(MaxTTL + time.Minute).Unix()
	if _, err := Sign(priv, c); err != ErrTTLTooLong {
		t.Fatalf("want ErrTTLTooLong, got %v", err)
	}
}

func TestSignRejectsWrongAudience(t *testing.T) {
	_, priv, _ := GenerateKey()
	c := baseClaims(time.Now())
	c.Audience = "someone-else"
	if _, err := Sign(priv, c); err != ErrAudience {
		t.Fatalf("want ErrAudience, got %v", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := GenerateKey()
	otherPub, _, _ := GenerateKey()
	now := time.Now()
	raw, _ := Sign(priv, baseClaims(now))
	if _, err := Verify(otherPub, raw, now); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestCheckManifest(t *testing.T) {
	c := Claims{Manifest: "abc"}
	if err := c.CheckManifest("abc"); err != nil {
		t.Fatalf("matching digest rejected: %v", err)
	}
	if err := c.CheckManifest("def"); err == nil {
		t.Fatal("mismatched digest accepted")
	}
	empty := Claims{}
	if err := empty.CheckManifest("anything"); err != nil {
		t.Fatalf("path-only token should skip manifest: %v", err)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]bool{
		"/var/www":        true,
		"/":               true,
		"var/www":         false,
		"/var/../etc":     false,
		"":                false,
		"/var/www/\x00xx": false,
	}
	for p, want := range cases {
		_, ok := NormalizePath(p)
		if ok != want {
			t.Errorf("NormalizePath(%q)=%v want %v", p, ok, want)
		}
	}
}

func TestPathCovered(t *testing.T) {
	if !PathCovered("/var/www", "/var/www/a/b") {
		t.Fatal("child not covered")
	}
	if PathCovered("/var/www", "/var/wwwroot") {
		t.Fatal("sibling prefix must not be covered")
	}
	if !PathCovered("/", "/etc/passwd") {
		t.Fatal("root should cover everything")
	}
}

func TestSignRequiresKey(t *testing.T) {
	c := baseClaims(time.Now())
	if _, err := Sign(ed25519.PrivateKey{}, c); err == nil {
		t.Fatal("expected error for invalid key")
	}
}
