//go:build linux

package enforcer

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// ensureSecurityFS mounts securityfs when it is not already mounted, so the
// active LSM list is readable on minimal images.
func ensureSecurityFS() {
	if _, err := os.Stat("/sys/kernel/security/lsm"); err == nil {
		return
	}
	_ = os.MkdirAll("/sys/kernel/security", 0o755)
	_ = unix.Mount("securityfs", "/sys/kernel/security", "securityfs", 0, "")
}

// ProbeReport is the result of a capability probe on this host.
type ProbeReport struct {
	KernelRelease string `json:"kernel_release"`
	KernelCmdline string `json:"kernel_cmdline"`
	LSMActive     string `json:"lsm_active"`
	LSMHasBPF     bool   `json:"lsm_has_bpf"`
	HasBTF        bool   `json:"has_btf"`
	BPFLoadError  string `json:"bpf_load_error,omitempty"`
	FanotifyError string `json:"fanotify_error,omitempty"`
	Selected      string `json:"selected"`
	Degraded      bool   `json:"degraded"`
}

// Probe inspects the host and reports which backend Select would pick, and why
// the stronger ones are unavailable. It actually loads and attaches the eBPF
// programs and initialises fanotify, so a node can be checked before rollout.
func Probe(stateDir string) ProbeReport {
	rep := ProbeReport{}
	ensureSecurityFS()
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		rep.KernelRelease = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile("/proc/cmdline"); err == nil {
		rep.KernelCmdline = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		rep.LSMActive = strings.TrimSpace(string(raw))
	}
	rep.LSMHasBPF = false
	for _, part := range strings.Split(rep.LSMActive, ",") {
		if strings.TrimSpace(part) == "bpf" {
			rep.LSMHasBPF = true
		}
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		rep.HasBTF = true
	}

	// Probe attaches real programs; keep the informational logs out of the
	// report.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(prev)

	if e, err := NewEBPF(nil); err == nil {
		_ = e.Close()
		rep.Selected = "ebpf-lsm"
		return rep
	} else {
		rep.BPFLoadError = err.Error()
	}
	if f, err := NewFanotify(stateDir, nil); err == nil {
		_ = f.Close()
		rep.Selected = "fanotify"
		rep.Degraded = true
		return rep
	} else {
		rep.FanotifyError = err.Error()
	}
	rep.Selected = "observe"
	rep.Degraded = true
	return rep
}

// SecurityFSMountHint returns a shell hint for mounting securityfs when the LSM
// list is not readable (common on minimal images).
func SecurityFSMountHint() string {
	if _, err := os.Stat("/sys/kernel/security/lsm"); err == nil {
		return ""
	}
	if out, err := exec.Command("sh", "-c", "mount -t securityfs securityfs /sys/kernel/security 2>&1").CombinedOutput(); err != nil {
		return strings.TrimSpace(string(out))
	}
	if raw, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		return "mounted on demand: " + strings.TrimSpace(string(bytes.TrimSpace(raw)))
	}
	return ""
}

// FormatProbe renders a report for humans.
func FormatProbe(r ProbeReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kernel        : %s\n", r.KernelRelease)
	fmt.Fprintf(&b, "cmdline       : %s\n", r.KernelCmdline)
	fmt.Fprintf(&b, "lsm active    : %s (bpf=%v)\n", r.LSMActive, r.LSMHasBPF)
	fmt.Fprintf(&b, "kernel BTF    : %v\n", r.HasBTF)
	if r.BPFLoadError != "" {
		fmt.Fprintf(&b, "eBPF LSM      : unavailable: %s\n", r.BPFLoadError)
	} else {
		fmt.Fprintf(&b, "eBPF LSM      : available\n")
	}
	if r.FanotifyError != "" {
		fmt.Fprintf(&b, "fanotify      : unavailable: %s\n", r.FanotifyError)
	} else {
		fmt.Fprintf(&b, "fanotify      : available\n")
	}
	fmt.Fprintf(&b, "selected      : %s (degraded=%v)\n", r.Selected, r.Degraded)
	return b.String()
}
