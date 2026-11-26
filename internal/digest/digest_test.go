package digest

import "testing"

func TestOfFilesDeterministic(t *testing.T) {
	a := []File{{Path: "index.html", SHA256: "aa"}, {Path: "app.js", SHA256: "bb"}}
	b := []File{{Path: "index.html", SHA256: "aa"}, {Path: "app.js", SHA256: "bb"}}
	if OfFiles(a) != OfFiles(b) {
		t.Fatal("digest is not deterministic")
	}
	if OfFiles(a) == OfFiles([]File{{Path: "index.html", SHA256: "aa"}, {Path: "app.js", SHA256: "cc"}}) {
		t.Fatal("digest ignores file content")
	}
}
