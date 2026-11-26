package uninstall

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestTicketSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := Nonce()
	if err != nil {
		t.Fatal(err)
	}
	tk := &Ticket{NodeID: "n_1", RequestID: "ur_1", Nonce: nonce}
	if err := Sign(priv, tk); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, tk, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Tampered fields must fail.
	bad := *tk
	bad.NodeID = "n_2"
	if err := Verify(pub, &bad, time.Now()); err == nil {
		t.Fatal("tampered node accepted")
	}
	// Wrong key must fail.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(pub2, tk, time.Now()); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Expired ticket must fail.
	old := time.Now().Add(20 * time.Minute)
	if err := Verify(pub, tk, old); err == nil {
		t.Fatal("expired ticket accepted")
	}
	// Encode/decode round-trip.
	enc, err := EncodeTicket(tk)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeTicket(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, dec, time.Now()); err != nil {
		t.Fatalf("decoded ticket: %v", err)
	}
}
