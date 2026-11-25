//go:build windows

package enforcer

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Probe reports which backend Select would pick on this Windows host.
func Probe(stateDir string) ProbeReport {
	rep := ProbeReport{OS: "windows"}
	if v := windows.RtlGetVersion(); v != nil {
		rep.KernelRelease = fmt.Sprintf("Windows %d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	}
	e, err := NewWindowsACL(nil, stateDir)
	if err != nil {
		rep.BPFLoadError = "windows-acl: " + err.Error()
		rep.Selected = "observe"
		rep.Degraded = true
		return rep
	}
	_ = e.Close()
	rep.LSMActive = "ntfs-acl"
	rep.Selected = "windows-acl"
	rep.Degraded = true
	return rep
}

// SecurityFSMountHint is Linux-specific.
func SecurityFSMountHint() string { return "" }
