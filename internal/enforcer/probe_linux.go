//go:build linux

package enforcer

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/easykeke/tamperguard/internal/landlock"
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

// Probe inspects the host and reports which backend Select would pick, and why
// the stronger ones are unavailable. It actually loads and attaches the eBPF
// programs and initialises fanotify, so a node can be checked before rollout.
func Probe(stateDir string) ProbeReport {
	rep := ProbeReport{OS: "linux"}
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
	if abi, err := landlock.ABI(); err == nil {
		rep.LandlockABI = abi
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
