package enforcer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// pinConfigMap persists the enforcement switch map so DetachPinned can disable
// protection without an agent process.
func pinConfigMap(m *ebpf.Map) error {
	if err := ensureBPFFS(); err != nil {
		return err
	}
	if err := os.MkdirAll(PinnedDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(PinnedDir, pinnedConfigName)
	_ = os.Remove(path)
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("pin config map: %w", err)
	}
	return nil
}
