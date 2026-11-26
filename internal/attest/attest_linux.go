// Package attest collects boot-integrity evidence and reports it to the control
// plane.
//
// This is evidence reporting, not cryptographic remote attestation: the agent
// reads Secure Boot state, TPM PCR values, IMA policy presence and the kernel
// command line, hashes them into one digest and sends that digest with every
// heartbeat. The control plane stores the latest value and logs changes, which
// makes an offline modification or a rescue-boot visible after the node comes
// back. Signing a TPM quote with an AK and verifying it server-side is the next
// step; this package deliberately does not claim that level yet.
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Evidence is the boot-integrity snapshot.
type Evidence struct {
	Digest     string            `json:"digest,omitempty"`
	SecureBoot string            `json:"secure_boot,omitempty"`
	TPM        bool              `json:"tpm,omitempty"`
	IMA        bool              `json:"ima,omitempty"`
	PCRs       map[string]string `json:"pcrs,omitempty"`
	CmdlineSHA string            `json:"cmdline_sha,omitempty"`
}

// Collect reads the available evidence below root ("/" in production, a fixture
// directory in tests).
func Collect(root string) Evidence {
	if root == "" {
		root = "/"
	}
	ev := Evidence{PCRs: map[string]string{}}
	ev.SecureBoot = secureBootState(root)
	ev.TPM = tpmPresent(root)
	ev.IMA = fileExists(filepath.Join(root, "sys/kernel/security/ima/policy"))
	if ev.TPM {
		for _, pcr := range []string{"0", "4", "7"} {
			p := filepath.Join(root, "sys/class/tpm/tpm0/pcr-sha256", pcr)
			if raw, err := os.ReadFile(p); err == nil {
				ev.PCRs[pcr] = strings.TrimSpace(string(raw))
			}
		}
	}
	ev.CmdlineSHA = hashOfFile(filepath.Join(root, "proc/cmdline"))
	ev.Digest = ev.digest()
	return ev
}

// Empty reports whether no evidence at all was collected.
func (e Evidence) Empty() bool { return e.Digest == "" }

func (e Evidence) digest() string {
	canonical := struct {
		SecureBoot string            `json:"sb"`
		TPM        bool              `json:"tpm"`
		IMA        bool              `json:"ima"`
		PCRs       map[string]string `json:"pcrs"`
		Cmdline    string            `json:"cmdline"`
	}{e.SecureBoot, e.TPM, e.IMA, e.PCRs, e.CmdlineSHA}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func secureBootState(root string) string {
	dir := filepath.Join(root, "sys/firmware/efi/efivars")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "unknown"
	}
	for _, ent := range entries {
		if !strings.HasPrefix(ent.Name(), "SecureBoot-") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil || len(raw) < 5 {
			return "unknown"
		}
		// efivar: 4 attribute bytes, then the value (1 = enabled).
		if raw[4] == 1 {
			return "enabled"
		}
		return "disabled"
	}
	return "unknown"
}

func tpmPresent(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "sys/class/tpm/tpm0")); err == nil {
		return true
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func hashOfFile(p string) string {
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Describe renders a one-line summary for logs and the UI.
func (e Evidence) Describe() string {
	if e.Empty() {
		return "no boot evidence available"
	}
	return fmt.Sprintf("secureboot=%s tpm=%t ima=%t pcrs=%d digest=%s",
		e.SecureBoot, e.TPM, e.IMA, len(e.PCRs), short(e.Digest))
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
