//go:build !windows

package watchdog

import "errors"

// Options is unused outside Windows.
type Options struct {
	Services    []string
	AgentDir    string
	StateDir    string
	PublishDir  string
	ServiceSDDL string
}

// Run reports that the watchdog is a Windows-only component.
func Run(Options) error {
	return errors.New("watchdog: only supported on Windows")
}
