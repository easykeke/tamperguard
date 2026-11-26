// Package tpmquote verifies a TPM 2.0 quote produced by `tpm2_quote`.
//
// The agent asks the TPM to sign a TPMS_ATTEST structure that binds a
// server-issued nonce and the selected PCR values. Verification needs only the
// AK public key and the wire structures, so the control plane does not need a
// TPM: it parses the attestation, checks the nonce and the PCR digest, then
// verifies the ECDSA signature over the attested bytes.
package tpmquote

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

const (
	tpmGeneratedMagic = 0xFF544347
	attestTypeQuote   = 0x8018
	algECC            = 0x0018
	algSHA256         = 0x000B
)

// Evidence is one quote submission.
type Evidence struct {
	Attest    []byte `json:"attest"`    // TPMS_ATTEST bytes
	Signature []byte `json:"signature"` // TPMT_SIGNATURE bytes
	PCR       []byte `json:"pcr"`       // concatenated PCR values, selected order
	Indexes   []int  `json:"indexes"`   // selected PCR indexes, e.g. [0,4,7]
}

// ParseAKPEM loads an ECDSA P-256 public key exported by `tpm2_readpublic -f pem`.
func ParseAKPEM(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("tpmquote: no PEM block in AK public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tpmquote: parse AK: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tpmquote: AK is not an ECDSA key")
	}
	return ec, nil
}

// Verify checks nonce binding, PCR digest and the ECDSA signature.
func Verify(ak *ecdsa.PublicKey, nonce []byte, ev Evidence) error {
	if ak == nil {
		return errors.New("tpmquote: missing AK public key")
	}
	if len(ev.Indexes) == 0 {
		return errors.New("tpmquote: no PCR selection")
	}
	extra, selected, pcrDigest, err := parseAttest(ev.Attest)
	if err != nil {
		return err
	}
	if !equalBytes(extra, nonce) {
		return errors.New("tpmquote: quote does not carry the server nonce")
	}
	if fmt.Sprint(selected) != fmt.Sprint(ev.Indexes) {
		return fmt.Errorf("tpmquote: PCR selection is %v, expected %v", selected, ev.Indexes)
	}
	want := sha256.Sum256(ev.PCR)
	if !equalBytes(pcrDigest, want[:]) {
		return errors.New("tpmquote: PCR values do not match the quote digest")
	}
	r, s, err := parseECSDSignature(ev.Signature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(ev.Attest)
	if !ecdsa.Verify(ak, digest[:], r, s) {
		return errors.New("tpmquote: signature does not verify against the AK")
	}
	return nil
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) u16() (uint16, error) {
	if r.off+2 > len(r.b) {
		return 0, errors.New("tpmquote: truncated")
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.off+4 > len(r.b) {
		return 0, errors.New("tpmquote: truncated")
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}

func (r *reader) u64() (uint64, error) {
	if r.off+8 > len(r.b) {
		return 0, errors.New("tpmquote: truncated")
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v, nil
}

func (r *reader) bytesN(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, errors.New("tpmquote: truncated")
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *reader) size16() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	return r.bytesN(int(n))
}

// parseAttest returns extraData, selected PCR indexes and the PCR digest.
func parseAttest(attest []byte) (extra []byte, selected []int, pcrDigest []byte, err error) {
	r := &reader{b: attest}
	magic, err := r.u32()
	if err != nil {
		return nil, nil, nil, err
	}
	if magic != tpmGeneratedMagic {
		return nil, nil, nil, errors.New("tpmquote: not a TPMS_ATTEST structure")
	}
	typ, err := r.u16()
	if err != nil {
		return nil, nil, nil, err
	}
	if typ != attestTypeQuote {
		return nil, nil, nil, fmt.Errorf("tpmquote: attestation type 0x%x is not a quote", typ)
	}
	if _, err := r.size16(); err != nil { // qualifiedSigner
		return nil, nil, nil, err
	}
	extra, err = r.size16()
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := r.u64(); err != nil { // clockInfo.clock
		return nil, nil, nil, err
	}
	if _, err := r.u32(); err != nil { // resetCount
		return nil, nil, nil, err
	}
	if _, err := r.u32(); err != nil { // restartCount
		return nil, nil, nil, err
	}
	if _, err := r.bytesN(1); err != nil { // safe
		return nil, nil, nil, err
	}
	if _, err := r.u64(); err != nil { // firmwareVersion
		return nil, nil, nil, err
	}
	count, err := r.u32()
	if err != nil {
		return nil, nil, nil, err
	}
	for i := uint32(0); i < count; i++ {
		alg, err := r.u16()
		if err != nil {
			return nil, nil, nil, err
		}
		sizeByte, err := r.bytesN(1)
		if err != nil {
			return nil, nil, nil, err
		}
		bitmap, err := r.bytesN(int(sizeByte[0]))
		if err != nil {
			return nil, nil, nil, err
		}
		if alg != algSHA256 {
			continue
		}
		for idx := 0; idx < 24; idx++ {
			byteIdx := idx / 8
			if byteIdx < len(bitmap) && bitmap[byteIdx]&(1<<uint(idx%8)) != 0 {
				selected = append(selected, idx)
			}
		}
	}
	pcrDigest, err = r.size16()
	if err != nil {
		return nil, nil, nil, err
	}
	return extra, selected, pcrDigest, nil
}

// parseECSDSignature parses TPMT_SIGNATURE for an ECDSA/SHA256 key.
func parseECSDSignature(sig []byte) (r, s *big.Int, err error) {
	rd := &reader{b: sig}
	alg, err := rd.u16()
	if err != nil {
		return nil, nil, err
	}
	if alg != algECC {
		return nil, nil, fmt.Errorf("tpmquote: signature algorithm 0x%x is not ECDSA", alg)
	}
	hashAlg, err := rd.u16()
	if err != nil {
		return nil, nil, err
	}
	if hashAlg != algSHA256 {
		return nil, nil, fmt.Errorf("tpmquote: signature hash 0x%x is not SHA-256", hashAlg)
	}
	rb, err := rd.size16()
	if err != nil {
		return nil, nil, err
	}
	sb, err := rd.size16()
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb), nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
