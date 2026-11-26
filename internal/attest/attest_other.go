//go:build !linux

package attest

// Evidence is empty on platforms without the Linux sysfs interfaces. Windows
// attestation is a separate implementation step, not silently faked here.
type Evidence struct {
	Digest     string            `json:"digest,omitempty"`
	SecureBoot string            `json:"secure_boot,omitempty"`
	TPM        bool              `json:"tpm,omitempty"`
	IMA        bool              `json:"ima,omitempty"`
	PCRs       map[string]string `json:"pcrs,omitempty"`
	CmdlineSHA string            `json:"cmdline_sha,omitempty"`
}

// Collect reports no evidence on this platform.
func Collect(string) Evidence { return Evidence{} }

// Empty reports whether no evidence was collected.
func (e Evidence) Empty() bool { return e.Digest == "" }

// Describe renders a one-line summary.
func (e Evidence) Describe() string { return "no boot evidence available" }
