package audit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func newChain(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *bytes.Buffer, []Record) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	w := NewWriter("agent-1", priv, buf, 1, "")
	var recs []Record
	for i := 0; i < 3; i++ {
		r, err := w.Append(Record{Kind: KindWriteBlocked, Path: "/var/www/a", Op: "open_write"})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		recs = append(recs, r)
	}
	return pub, priv, buf, recs
}

func TestChainVerifies(t *testing.T) {
	pub, _, buf, recs := newChain(t)
	if len(recs) != 3 || buf.Len() == 0 {
		t.Fatal("writer produced nothing")
	}
	if recs[0].Seq != 1 || recs[1].Seq != 2 || recs[2].Seq != 3 {
		t.Fatalf("unexpected sequence: %d %d %d", recs[0].Seq, recs[1].Seq, recs[2].Seq)
	}
	v := NewVerifier(pub)
	st, err := v.VerifyAll("agent-1", recs)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if st.NextSeq != 4 || st.LastHash != recs[2].Hash {
		t.Fatalf("bad terminal state: %+v", st)
	}
}

func TestChainDetectsModification(t *testing.T) {
	pub, _, _, recs := newChain(t)
	recs[1].Path = "/var/www/evil"
	if _, err := NewVerifier(pub).VerifyAll("agent-1", recs); !errors.Is(err, ErrHash) {
		t.Fatalf("want ErrHash, got %v", err)
	}
}

func TestChainDetectsDeletion(t *testing.T) {
	pub, _, _, recs := newChain(t)
	spliced := []Record{recs[0], recs[2]}
	if _, err := NewVerifier(pub).VerifyAll("agent-1", spliced); !errors.Is(err, ErrSequence) {
		t.Fatalf("want ErrSequence, got %v", err)
	}
}

func TestChainDetectsReplayAfterTruncation(t *testing.T) {
	pub, _, _, recs := newChain(t)
	v := NewVerifier(pub)
	st := &ChainState{AgentID: "agent-1", NextSeq: 1}
	for _, r := range recs {
		if err := v.Next(st, r); err != nil {
			t.Fatalf("next: %v", err)
		}
	}
	// Replaying an already-consumed record must fail.
	if err := v.Next(st, recs[0]); !errors.Is(err, ErrSequence) && !errors.Is(err, ErrPrevHash) {
		t.Fatalf("replay not detected: %v", err)
	}
}

func TestChainDetectsForeignSignature(t *testing.T) {
	_, _, _, recs := newChain(t)
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := NewVerifier(wrongPub).VerifyAll("agent-1", recs); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestWriterOutputIsJSONLines(t *testing.T) {
	_, _, buf, _ := newChain(t)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}
	for _, ln := range lines {
		if !strings.HasPrefix(ln, "{") || !strings.Contains(ln, `"seq"`) {
			t.Fatalf("not a record line: %s", ln)
		}
	}
}

func TestVerifyRangeAllowsPurgedHead(t *testing.T) {
	pub, _, _, recs := newChain(t)
	v := NewVerifier(pub)

	// Simulate retention: the oldest record is gone, the rest must still verify.
	fromSeq, err := v.VerifyRange(recs[1:])
	if err != nil {
		t.Fatalf("verify range: %v", err)
	}
	if fromSeq != 2 {
		t.Fatalf("from_seq = %d, want 2", fromSeq)
	}

	// A gap inside the range is still an error.
	if _, err := v.VerifyRange([]Record{recs[0], recs[2]}); !errors.Is(err, ErrSequence) {
		t.Fatalf("want ErrSequence for a gap, got %v", err)
	}

	// Tampering inside the range is still detected.
	tampered := append([]Record(nil), recs[1:]...)
	tampered[0].Path = "/var/www/evil"
	if _, err := v.VerifyRange(tampered); !errors.Is(err, ErrHash) {
		t.Fatalf("want ErrHash for tampered record, got %v", err)
	}
}
