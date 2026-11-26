//go:build windows

package enforcer

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Mandatory Integrity Control (MIC) support.
//
// Access is decided in two steps on Windows: the DACL answers "who may write",
// MIC answers "what integrity level may write". For tamper protection the
// combination is a high label with NO_WRITE_UP: a process below that level is
// denied even though its token holds every privilege the DACL would need. The
// label must be applied by a process whose own integrity is at least as high
// (Windows rejects raising a label above the caller), which is why the strict
// "System" mode requires the LocalSystem service.
//
// The SACL is built from an SDDL string and applied with SetFileSecurityW,
// followed by a read-back check: an earlier hand-built ACL was accepted by the
// API but never took effect, and silent failure is the worst outcome for a
// protection layer.

var (
	modadvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procSetFileSecurity = modadvapi32.NewProc("SetFileSecurityW")
)

const mandatoryLabelNoWriteUp = 0x00000001

// integritySID returns the string form of the integrity SID for a level.
func integritySIDString(level integrityLevel) (string, bool) {
	switch level {
	case levelLow:
		return "S-1-16-4096", true
	case levelMedium:
		return "S-1-16-8192", true
	case levelHigh:
		return "S-1-16-12288", true
	case levelSystem:
		return "S-1-16-16384", true
	default:
		return "", false
	}
}

// setIntegrity labels path with NO_WRITE_UP at the given level. It verifies the
// result and falls back to `icacls` when the native path had no effect.
func setIntegrity(path string, level integrityLevel, inherit bool) error {
	sid, ok := integritySIDString(level)
	if !ok {
		return fmt.Errorf("windows-acl: unknown integrity level %d", level)
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("S:(ML;%s;NW;;;%s)", flags, sid)
	_ = mandatoryLabelNoWriteUp // documented constant, NW is the SDDL form

	nativeErr := applySACL(path, sddl)
	if nativeErr == nil {
		if got, err := integrityOf(path); err == nil && got == level {
			return nil
		}
	}

	// Fallback: icacls is present on every supported Windows version and knows
	// the label syntax; verify its effect as well.
	name := map[integrityLevel]string{
		levelLow:    "Low",
		levelMedium: "Medium",
		levelHigh:   "High",
		levelSystem: "System",
	}[level]
	inh := ""
	if inherit {
		inh = "(OI)(CI)"
	}
	out, err := exec.Command("icacls.exe", path, "/setintegritylevel", inh+name).CombinedOutput()
	if err == nil {
		if got, rerr := integrityOf(path); rerr == nil && got == level {
			return nil
		}
	}
	return fmt.Errorf("windows-acl: cannot set integrity %s on %s (native: %v; icacls: %v %s)",
		levelName(level), path, nativeErr, err, string(out))
}

// applySACL converts an SDDL SACL and applies it with SetFileSecurityW.
func applySACL(path string, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("SDDL %q: %w", sddl, err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	info := uint32(windows.SACL_SECURITY_INFORMATION)
	r, _, callErr := procSetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPtr)), uintptr(info), uintptr(unsafe.Pointer(sd)))
	if r == 0 {
		return fmt.Errorf("SetFileSecurityW: %w", callErr)
	}
	return nil
}

// enablePrivilege enables a privilege in the current process token.
func enablePrivilege(name string) error {
	var token windows.Token
	//nolint:staticcheck // OpenProcessToken expects a Handle; CurrentProcess is it.
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1}
	state.Privileges[0].Luid = luid
	state.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	return windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil)
}

// integrityOf reads the current label. It returns levelUnknown when the object
// has no mandatory label.
func integrityOf(path string) (integrityLevel, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return levelUnknown, err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return levelUnknown, err
	}
	if sacl == nil || sacl.AceCount == 0 {
		return levelUnknown, nil
	}
	for i := 0; i < int(sacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(sacl, uint32(i), &ace); err != nil {
			continue
		}
		if ace.Header.AceType != systemMandatoryLabelAceType {
			continue
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(&ace.SidStart)), 32)
		count := int(raw[1])
		if count < 1 || count > 15 {
			return levelUnknown, nil
		}
		off := 8 + 4*(count-1)
		return mapLabelSID(*(*uint32)(unsafe.Pointer(&raw[off]))), nil
	}
	return levelUnknown, nil
}

func mapLabelSID(subauth uint32) integrityLevel {
	switch subauth {
	case 4096:
		return levelLow
	case 8192:
		return levelMedium
	case 12288:
		return levelHigh
	case 16384:
		return levelSystem
	default:
		return levelUnknown
	}
}

// integrityLevel is the subset of Windows integrity labels this package uses.
type integrityLevel int

const (
	levelUnknown integrityLevel = 0
	levelLow     integrityLevel = 1
	levelMedium  integrityLevel = 2
	levelHigh    integrityLevel = 3
	levelSystem  integrityLevel = 4
)

const systemMandatoryLabelAceType = 0x11

// levelName renders a level for logs and the capability string.
func levelName(l integrityLevel) string {
	switch l {
	case levelLow:
		return "low"
	case levelMedium:
		return "medium"
	case levelHigh:
		return "high"
	case levelSystem:
		return "system"
	default:
		return "unknown"
	}
}

// parseLevel maps a configuration string to a level. "off"/"none" disables MIC.
func parseLevel(s string) (integrityLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "system":
		return levelSystem, true
	case "high":
		return levelHigh, true
	case "medium":
		return levelMedium, true
	case "low":
		return levelLow, true
	case "off", "none", "disabled":
		return levelUnknown, true
	default:
		return levelUnknown, false
	}
}

// levelFromSID reads the last sub-authority of a mandatory label SID.
func levelFromSID(sid *windows.SID) integrityLevel {
	if sid == nil {
		return levelUnknown
	}
	ptr := unsafe.Pointer(sid)
	count := *(*byte)(unsafe.Add(ptr, 1))
	if count < 1 || count > 15 {
		return levelUnknown
	}
	off := 8 + 4*(int(count)-1)
	return mapLabelSID(*(*uint32)(unsafe.Add(ptr, off)))
}

// currentTokenIntegrity returns the integrity level of the current process
// token. A process cannot label an object above its own level, so the agent
// downgrades the configured level instead of failing every update.
func currentTokenIntegrity() integrityLevel {
	tok := windows.GetCurrentProcessToken()
	var size uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return levelUnknown
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return levelUnknown
	}
	type sidAndAttributes struct {
		Sid        *windows.SID
		Attributes uint32
	}
	type tokenMandatoryLabel struct {
		Label sidAndAttributes
	}
	tml := (*tokenMandatoryLabel)(unsafe.Pointer(&buf[0]))
	return levelFromSID(tml.Label.Sid)
}
