//go:build linux

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// PinnedConfig is the pinned enforcement switch map. Writing 0 disables every
// hooked program, which makes `ebpf-detach` effective even on kernels that keep
// an LSM link attached after the pin is removed.
const pinnedConfigName = "tg_config"

// PinnedDir is where the LSM links are pinned so enforcement survives the agent
// process. A pinned link keeps the program attached to the kernel hook even if
// the agent is killed with SIGKILL; the next agent start removes stale pins and
// attaches fresh programs.
const PinnedDir = "/sys/fs/bpf/tamperguard"

// pinningEnabled reports whether links should be pinned. Tests set TG_EBPF_PIN=0
// so their temporary directories can be removed while enforcement is torn down.
func pinningEnabled() bool {
	v := os.Getenv("TG_EBPF_PIN")
	return v != "0" && v != "false"
}

func bpffsMounted() bool {
	raw, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "/sys/fs/bpf" {
			return true
		}
	}
	return false
}

// ensureBPFFS mounts bpffs when it is not mounted yet.
func ensureBPFFS() error {
	if bpffsMounted() {
		return nil
	}
	if err := os.MkdirAll("/sys/fs/bpf", 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("bpffs", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs: %w", err)
	}
	return nil
}

// pinLink persists one link under PinnedDir. Pinning is best effort: a kernel or
// container without bpffs still enforces while the agent runs.
func pinLink(name string, l link.Link) (string, error) {
	if err := ensureBPFFS(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(PinnedDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(PinnedDir, name)
	// A stale entry from a previous run must be removed first.
	_ = os.Remove(path)
	if err := l.Pin(path); err != nil {
		return "", fmt.Errorf("pin %s: %w", name, err)
	}
	return path, nil
}

// DetachPinned disables enforcement through the pinned config map, then closes
// and removes every pinned link. It is used by `tg-agent ebpf-detach`
// (maintenance), by uninstall, and on startup to clear stale links left behind by
// a crashed agent.
func DetachPinned() (int, error) {
	if !bpffsMounted() {
		return 0, nil
	}
	// Disable first: this is what actually stops blocking, independent of how
	// the kernel handles link detach.
	mapPath := filepath.Join(PinnedDir, pinnedConfigName)
	if m, err := ebpf.LoadPinnedMap(mapPath, nil); err == nil {
		_ = m.Update(uint32(0), uint32(0), ebpf.UpdateAny)
		_ = m.Close()
		_ = os.Remove(mapPath)
	}
	entries, err := os.ReadDir(PinnedDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	count := 0
	var firstErr error
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		path := filepath.Join(PinnedDir, ent.Name())
		l, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			// A file that is not a link: remove it so it cannot confuse startup.
			_ = os.Remove(path)
			continue
		}
		// Unpin first: the bpffs entry is the persistent reference. Closing the
		// fd while the pin exists leaves the link alive on some kernels.
		if err := l.Unpin(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
		count++
	}
	return count, firstErr
}
