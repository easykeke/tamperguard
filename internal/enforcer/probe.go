package enforcer

import (
	"fmt"
	"strings"
)

// ProbeReport is the result of a capability probe on this host.
type ProbeReport struct {
	OS            string `json:"os"`
	KernelRelease string `json:"kernel_release"`
	KernelCmdline string `json:"kernel_cmdline"`
	LSMActive     string `json:"lsm_active"`
	LSMHasBPF     bool   `json:"lsm_has_bpf"`
	HasBTF        bool   `json:"has_btf"`
	BPFLoadError  string `json:"bpf_load_error,omitempty"`
	FanotifyError string `json:"fanotify_error,omitempty"`
	LandlockABI   int    `json:"landlock_abi,omitempty"`
	FSVerity      string `json:"fsverity,omitempty"`
	Selected      string `json:"selected"`
	Degraded      bool   `json:"degraded"`
}

// FormatProbe renders a report for humans.
func FormatProbe(r ProbeReport) string {
	var b strings.Builder
	osName := r.OS
	if osName == "" {
		osName = "linux"
	}
	fmt.Fprintf(&b, "os            : %s\n", osName)
	fmt.Fprintf(&b, "kernel        : %s\n", r.KernelRelease)
	if r.KernelCmdline != "" {
		fmt.Fprintf(&b, "cmdline       : %s\n", r.KernelCmdline)
	}
	if r.LSMActive != "" {
		fmt.Fprintf(&b, "lsm active    : %s (bpf=%v)\n", r.LSMActive, r.LSMHasBPF)
	}
	if osName == "linux" {
		fmt.Fprintf(&b, "kernel BTF    : %v\n", r.HasBTF)
		if r.LandlockABI > 0 {
			fmt.Fprintf(&b, "landlock      : ABI v%d (process self-protection available)\n", r.LandlockABI)
		} else {
			fmt.Fprintf(&b, "landlock      : unavailable (process self-protection disabled)\n")
		}
		if r.FSVerity != "" {
			fmt.Fprintf(&b, "fs-verity     : %s\n", r.FSVerity)
		}
	}
	if r.BPFLoadError != "" {
		fmt.Fprintf(&b, "strongest     : unavailable: %s\n", r.BPFLoadError)
	}
	if r.FanotifyError != "" {
		fmt.Fprintf(&b, "fallback      : unavailable: %s\n", r.FanotifyError)
	}
	fmt.Fprintf(&b, "selected      : %s (degraded=%v)\n", r.Selected, r.Degraded)
	return b.String()
}
