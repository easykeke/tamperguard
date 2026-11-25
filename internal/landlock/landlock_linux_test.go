//go:build linux

package landlock

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const helperEnv = "TG_LANDLOCK_HELPER"

// TestLandlockHelper runs inside a child process after Restrict. It is not a
// real test: markers on stdout tell the parent which operation slipped through.
func TestLandlockHelper(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper process only")
	}
	ro := os.Getenv("TG_LANDLOCK_RO")
	rw := os.Getenv("TG_LANDLOCK_RW")
	if err := Restrict(Config{WritableDirs: []string{rw}}); err != nil {
		fmt.Println("RESTRICT_ERR:", err)
		os.Exit(10)
	}
	if _, err := os.ReadFile(filepath.Join(ro, "index.html")); err != nil {
		fmt.Println("READ_FAIL:", err)
		os.Exit(11)
	}
	if err := os.WriteFile(filepath.Join(rw, "ok.txt"), []byte("ok"), 0o644); err != nil {
		fmt.Println("RW_WRITE_FAIL:", err)
		os.Exit(12)
	}
	if err := os.WriteFile(filepath.Join(ro, "index.html"), []byte("evil"), 0o644); err == nil {
		fmt.Println("RO_OVERWRITE_ALLOWED")
		os.Exit(13)
	}
	if err := os.WriteFile(filepath.Join(ro, "new.txt"), []byte("evil"), 0o644); err == nil {
		fmt.Println("RO_CREATE_ALLOWED")
		os.Exit(14)
	}
	if err := os.Remove(filepath.Join(ro, "index.html")); err == nil {
		fmt.Println("RO_DELETE_ALLOWED")
		os.Exit(15)
	}
	os.Exit(0)
}

func TestRestrictDeniesWritesOutsideAllowList(t *testing.T) {
	if _, err := ABI(); err != nil {
		t.Skipf("landlock unavailable: %v", err)
	}
	base := t.TempDir()
	ro := filepath.Join(base, "site")
	rw := filepath.Join(base, "writable")
	for _, dir := range []string{ro, rw} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	original := []byte("original")
	if err := os.WriteFile(filepath.Join(ro, "index.html"), original, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLandlockHelper")
	cmd.Env = append(os.Environ(),
		helperEnv+"=1",
		"TG_LANDLOCK_RO="+ro,
		"TG_LANDLOCK_RW="+rw,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("confined helper failed: %v\n%s", err, out)
	}
	if got, err := os.ReadFile(filepath.Join(ro, "index.html")); err != nil || string(got) != string(original) {
		t.Fatalf("protected file changed inside the sandbox: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(rw, "ok.txt")); err != nil {
		t.Fatalf("allowed write did not land: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ro, "new.txt")); err == nil {
		t.Fatal("new file was created in the read-only tree")
	}
}
