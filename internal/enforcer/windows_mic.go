//go:build windows

package enforcer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Mandatory Integrity Control (MIC) support.
//
// Access is decided in two steps on Windows: the DACL answers "who may write",
// MIC answers "what integrity level may write". For tamper protection the
// interesting combination is a System-integrity label with NO_WRITE_UP: an
// administrator elevated to High integrity cannot modify the object even though
// its token holds every privilege the DACL would need. Only System-integrity
// processes (services such as the agent itself) can write, and during a release
// window the label is lowered to Medium so the authorised publisher account can
// write through the DACL grant.
//
// Writing a SACL needs SeSecurityPrivilege, so the agent must run elevated; the
// label is written with inheritance so new files under a protected directory are
// covered as well.

var (
	advapi32DLL         = windows.NewLazySystemDLL("advapi32.dll")
	procInitializeACL   = advapi32DLL.NewProc("InitializeAcl")
	procAddMandatoryAce = advapi32DLL.NewProc("AddMandatoryAce")
)

const (
	aclRevision                 = 2
	mandatoryLabelNoWriteUp     = 0x00000001
	systemMandatoryLabelAceType = 0x11
)

// integrityLevel is the subset of Windows integrity labels this package uses.
type integrityLevel int

const (
	levelUnknown integrityLevel = 0
	levelLow     integrityLevel = 1
	levelMedium  integrityLevel = 2
	levelHigh    integrityLevel = 3
	levelSystem  integrityLevel = 4
)

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

func sidForLevel(level integrityLevel) (windows.WELL_KNOWN_SID_TYPE, bool) {
	switch level {
	case levelLow:
		return windows.WELL_KNOWN_SID_TYPE(windows.WinLowLabelSid), true
	case levelMedium:
		return windows.WELL_KNOWN_SID_TYPE(windows.WinMediumLabelSid), true
	case levelHigh:
		return windows.WELL_KNOWN_SID_TYPE(windows.WinHighLabelSid), true
	case levelSystem:
		return windows.WELL_KNOWN_SID_TYPE(windows.WinSystemLabelSid), true
	default:
		return 0, false
	}
}

// setIntegrity writes a mandatory label ACE into the object's SACL, with
// NO_WRITE_UP so lower-integrity processes cannot write even with a permissive
// DACL.
func setIntegrity(path string, level integrityLevel, inherit bool) error {
	kind, ok := sidForLevel(level)
	if !ok {
		return fmt.Errorf("windows-acl: unknown integrity level %d", level)
	}
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		return err
	}
	sidLen := int(windows.GetLengthSid(sid))
	// ACL header (8) + ACE header+mask (8) + SID.
	aclSize := 8 + 8 + sidLen
	buf := make([]byte, aclSize)
	acl := (*windows.ACL)(unsafe.Pointer(&buf[0]))
	if r, _, callErr := procInitializeACL.Call(
		uintptr(unsafe.Pointer(acl)), uintptr(aclSize), aclRevision); r == 0 {
		return fmt.Errorf("InitializeAcl: %w", callErr)
	}
	var flags uintptr
	if inherit {
		flags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if r, _, callErr := procAddMandatoryAce.Call(
		uintptr(unsafe.Pointer(acl)), aclRevision, flags,
		mandatoryLabelNoWriteUp, uintptr(unsafe.Pointer(sid))); r == 0 {
		return fmt.Errorf("AddMandatoryAce: %w", callErr)
	}
	info := windows.SECURITY_INFORMATION(windows.SACL_SECURITY_INFORMATION |
		windows.PROTECTED_SACL_SECURITY_INFORMATION)
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, nil, acl)
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
		// SID layout: revision, sub-authority count, authority[6], sub-auth[count].
		raw := unsafe.Slice((*byte)(unsafe.Pointer(&ace.SidStart)), 32)
		count := int(raw[1])
		if count < 1 || count > 15 {
			return levelUnknown, nil
		}
		off := 8 + 4*(count-1)
		switch *(*uint32)(unsafe.Pointer(&raw[off])) {
		case 4096:
			return levelLow, nil
		case 8192:
			return levelMedium, nil
		case 12288:
			return levelHigh, nil
		case 16384:
			return levelSystem, nil
		default:
			return levelUnknown, nil
		}
	}
	return levelUnknown, nil
}
