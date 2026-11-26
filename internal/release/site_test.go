package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sampleSite() *SiteManifest {
	return &SiteManifest{
		NodeID:    "n_1",
		RequestID: "pr_1",
		Manifest:  "sha256:abc",
		TargetDir: "/var/www/site",
		Files: []SiteFile{
			{Path: "static/app.js", SHA256: "b", Size: 10},
			{Path: "index.html", SHA256: "a", Size: 20},
		},
	}
}

func TestSiteManifestSignVerify(t *testing.T) {
	pub, priv := testKey(t)
	m := sampleSite()
	if err := SignSiteManifest(priv, m); err != nil {
		t.Fatal(err)
	}
	if m.SignedAt == 0 || m.Signature == "" {
		t.Fatal("signature not set")
	}
	if err := VerifySiteManifest(pub, m); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The canonical form sorts files.
	if m.Files[0].Path != "index.html" {
		t.Fatalf("files not sorted: %v", m.Files)
	}

	// Any field change must invalidate the signature.
	m.TargetDir = "/var/www/other"
	if err := VerifySiteManifest(pub, m); err == nil {
		t.Fatal("tampered target_dir accepted")
	}
	m2 := sampleSite()
	if err := SignSiteManifest(priv, m2); err != nil {
		t.Fatal(err)
	}
	m2.Files[0].SHA256 = "c"
	if err := VerifySiteManifest(pub, m2); err == nil {
		t.Fatal("tampered file hash accepted")
	}
}

func TestSiteManifestRejectsWrongKey(t *testing.T) {
	pubA, privA := testKey(t)
	_, privB := testKey(t)
	m := sampleSite()
	if err := SignSiteManifest(privA, m); err != nil {
		t.Fatal(err)
	}
	if err := VerifySiteManifest(pubA, m); err != nil {
		t.Fatalf("verify: %v", err)
	}
	m2 := sampleSite()
	if err := SignSiteManifest(privB, m2); err != nil {
		t.Fatal(err)
	}
	if err := VerifySiteManifest(pubA, m2); err == nil {
		t.Fatal("manifest signed by another key accepted")
	}
}

func TestSiteManifestRequiresSignature(t *testing.T) {
	pub, _ := testKey(t)
	m := sampleSite()
	if err := VerifySiteManifest(pub, m); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
}
