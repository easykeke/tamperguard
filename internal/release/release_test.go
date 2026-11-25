package release

import (
	"crypto/ed25519"
	"testing"
)

func testManifest() Manifest {
	return Manifest{
		Version: "0.2.0",
		OS:      "linux",
		Arch:    "amd64",
		SHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Size:    12345,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := testManifest()
	if err := m.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := m.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.Signature == "" {
		t.Fatal("signature not set")
	}
	// The canonical string must contain every field.
	want := "tg-release-v1:0.2.0:linux/amd64:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:12345"
	if m.Encode() != want {
		t.Fatalf("encode = %q, want %q", m.Encode(), want)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := testManifest()
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Manifest){
		func(x *Manifest) { x.Version = "9.9.9" },
		func(x *Manifest) { x.SHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" },
		func(x *Manifest) { x.Size = 1 },
		func(x *Manifest) { x.Signature = "00" },
	}
	for i, mutate := range cases {
		bad := m
		mutate(&bad)
		if err := bad.Verify(pub); err == nil {
			t.Errorf("case %d: tampered manifest accepted", i)
		}
	}
}

func TestValidateRejectsPathInjection(t *testing.T) {
	m := testManifest()
	m.Version = "../../etc/passwd"
	if err := m.Validate(); err == nil {
		t.Fatal("path-like version accepted")
	}
	m = testManifest()
	m.Size = 0
	if err := m.Validate(); err == nil {
		t.Fatal("zero size accepted")
	}
}
