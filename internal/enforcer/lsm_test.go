//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLSMHasBPF(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]bool{
		"lockdown,capability,landlock,yama,apparmor":     false,
		"lockdown,capability,landlock,yama,apparmor,bpf": true,
		"bpf":                           true,
		"":                              false,
		"lockdown,bpf_trace,capability": false,
		"lockdown, capability, bpf\n":   true,
	}
	for content, want := range cases {
		p := filepath.Join(dir, "lsm")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := lsmHasBPF(p); got != want {
			t.Fatalf("%q: got %v, want %v", content, got, want)
		}
	}
	if lsmHasBPF(filepath.Join(dir, "missing")) {
		t.Fatal("missing file reported bpf active")
	}
}
