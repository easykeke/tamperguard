package publish

import (
	"path/filepath"
	"testing"
)

func TestProfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := &Profile{
		NodeID:    "n_1",
		SourceDir: "/srv/release",
		TargetDir: "/var/www/site",
		Mode:      "incremental",
		Delivery:  "pull",
	}
	if err := SaveProfile(dir, p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProfile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *p {
		t.Fatalf("got %+v, want %+v", got, p)
	}
	if _, err := LoadProfile(filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("missing profile should be empty, got %v", err)
	}
}
