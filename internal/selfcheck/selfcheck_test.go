package selfcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildCompare(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "agent")
	b := filepath.Join(dir, "unit")
	if err := os.WriteFile(a, []byte("binary-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("unit-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Build([]string{a, b, filepath.Join(dir, "missing")})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(m.Files))
	}
	diffs, err := Compare(m)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("clean compare: %v %v", diffs, err)
	}
	if err := os.WriteFile(a, []byte("binary-EVIL"), 0o600); err != nil {
		t.Fatal(err)
	}
	diffs, err = Compare(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 1 || diffs[0].Missing {
		t.Fatalf("diffs = %+v", diffs)
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	diffs, _ = Compare(m)
	if len(diffs) != 2 || !diffs[1].Missing {
		t.Fatalf("expected missing diff, got %+v", diffs)
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Build([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "baseline.json")
	if err := Save(path, m); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || got.Files[0].SHA256 != m.Files[0].SHA256 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
