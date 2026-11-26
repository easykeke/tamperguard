package publish

import "testing"

func TestChangedOnly(t *testing.T) {
	full := &Manifest{Entries: []Entry{
		{Rel: "index.html", SHA256: "aaa", Size: 1},
		{Rel: "app.js", SHA256: "bbb", Size: 2},
		{Rel: "new.css", SHA256: "ccc", Size: 3},
	}}
	known := map[string]string{
		"index.html": "aaa", // unchanged
		"app.js":     "old", // changed
	}
	changed, skipped := changedOnly(full, known)
	if skipped != 1 {
		t.Fatalf("skipped=%d, want 1", skipped)
	}
	if len(changed.Entries) != 2 {
		t.Fatalf("changed=%d, want 2", len(changed.Entries))
	}
	if changed.Digest == "" || changed.Digest == full.Digest {
		t.Fatalf("digest not recomputed: %q", changed.Digest)
	}
	// Everything unchanged -> empty manifest, and it must be usable as "nothing".
	all, skipped := changedOnly(full, map[string]string{"index.html": "aaa", "app.js": "bbb", "new.css": "ccc"})
	if skipped != 3 || len(all.Entries) != 0 {
		t.Fatalf("skipped=%d entries=%d", skipped, len(all.Entries))
	}
}
