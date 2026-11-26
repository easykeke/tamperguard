//go:build linux

package attest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectEvidence(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, data []byte) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", []byte{0, 0, 0, 0, 1})
	mk("sys/class/tpm/tpm0/pcr-sha256/0", []byte("pcr0-value"))
	mk("sys/class/tpm/tpm0/pcr-sha256/4", []byte("pcr4-value"))
	mk("sys/kernel/security/ima/policy", []byte("policy"))
	mk("proc/cmdline", []byte("BOOT_IMAGE=/vmlinuz lsm=lockdown,bpf"))

	ev := Collect(root)
	if ev.SecureBoot != "enabled" || !ev.TPM || !ev.IMA {
		t.Fatalf("evidence = %+v", ev)
	}
	if ev.PCRs["0"] != "pcr0-value" || len(ev.PCRs) != 2 {
		t.Fatalf("pcrs = %+v", ev.PCRs)
	}
	if ev.Digest == "" {
		t.Fatal("empty digest")
	}
	first := ev.Digest

	// A changed kernel command line must change the digest (offline tamper).
	mk("proc/cmdline", []byte("BOOT_IMAGE=/vmlinuz lsm=lockdown,bpf init=/bin/sh"))
	if got := Collect(root).Digest; got == first {
		t.Fatal("digest did not change with the command line")
	}
}
