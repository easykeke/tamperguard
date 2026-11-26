package tpmquote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildAttest marshals a TPMS_ATTEST quote for tests.
func buildAttest(nonce, pcrValues []byte, indexes []int) []byte {
	var b []byte
	u16 := func(v uint16) { b = binary.BigEndian.AppendUint16(b, v) }
	u32 := func(v uint32) { b = binary.BigEndian.AppendUint32(b, v) }
	u64 := func(v uint64) { b = binary.BigEndian.AppendUint64(b, v) }

	u32(tpmGeneratedMagic)
	u16(attestTypeQuote)
	u16(0) // qualifiedSigner: empty
	u16(uint16(len(nonce)))
	b = append(b, nonce...)
	u64(1) // clock
	u32(0)
	u32(0)
	b = append(b, 0) // safe
	u64(1)           // firmwareVersion
	u32(1)           // one selection
	u16(algSHA256)
	b = append(b, 3) // sizeofSelect
	bitmap := make([]byte, 3)
	for _, idx := range indexes {
		bitmap[idx/8] |= 1 << uint(idx%8)
	}
	b = append(b, bitmap...)
	digest := sha256.Sum256(pcrValues)
	u16(uint16(len(digest)))
	b = append(b, digest[:]...)
	return b
}

func ecdsaSignature(pub *ecdsa.PrivateKey, attest []byte) []byte {
	digest := sha256.Sum256(attest)
	r, s, err := ecdsa.Sign(rand.Reader, pub, digest[:])
	if err != nil {
		panic(err)
	}
	rb := r.Bytes()
	sb := s.Bytes()
	var b []byte
	u16 := func(v uint16) { b = binary.BigEndian.AppendUint16(b, v) }
	u16(algECC)
	u16(algSHA256)
	u16(uint16(len(rb)))
	b = append(b, rb...)
	u16(uint16(len(sb)))
	b = append(b, sb...)
	return b
}

func TestVerifyQuote(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("server-nonce-123")
	pcr := make([]byte, 3*32)
	for i := range pcr {
		pcr[i] = byte(i)
	}
	attest := buildAttest(nonce, pcr, []int{0, 4, 7})
	sig := ecdsaSignature(priv, attest)
	ev := Evidence{Attest: attest, Signature: sig, PCR: pcr, Indexes: []int{0, 4, 7}}
	if err := Verify(&priv.PublicKey, nonce, ev); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Wrong nonce.
	if err := Verify(&priv.PublicKey, []byte("other"), ev); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	// Tampered PCR values.
	badPCR := append([]byte(nil), pcr...)
	badPCR[0] ^= 0xFF
	if err := Verify(&priv.PublicKey, nonce, Evidence{Attest: attest, Signature: sig, PCR: badPCR, Indexes: []int{0, 4, 7}}); err == nil {
		t.Fatal("tampered PCR accepted")
	}
	// Tampered attestation invalidates the signature.
	badAttest := append([]byte(nil), attest...)
	badAttest[len(badAttest)-1] ^= 0xFF
	if err := Verify(&priv.PublicKey, nonce, Evidence{Attest: badAttest, Signature: sig, PCR: pcr, Indexes: []int{0, 4, 7}}); err == nil {
		t.Fatal("tampered attestation accepted")
	}
	// Wrong key.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := Verify(&other.PublicKey, nonce, ev); err == nil {
		t.Fatal("wrong AK accepted")
	}
}
