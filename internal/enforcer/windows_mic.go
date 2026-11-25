//go:build windows

package enforcer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Mandatory Integrity Control (MIC) support.
//
// The ACL backend answers "who may write". MIC answers "what integrity level
// may write": an object labelled High with SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
// cannot be modified by a Medium-integrity process even when its DACL grants
// write access. That makes the protection survive a misconfigured or maliciously
// widened DACL, which is exactly the gap the ACL backend has on Windows.
//
// Writing a SACL needs SeSecurityPrivilege, so the agent must run elevated; the
// label is written with inheritance so new files under a protected directory
// are covered as well.

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

// setIntegrityLevel writes a mandatory label ACE into the object's SACL.
// high=true labels the object High with NO_WRITE_UP; high=false resets it to
// Medium (the normal state for user content).
func setIntegrityLevel(path string, high, inherit bool) error {
	kind := windows.WELL_KNOWN_SID_TYPE(windows.WinMediumLabelSid)
	if high {
		kind = windows.WELL_KNOWN_SID_TYPE(windows.WinHighLabelSid)
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
	info := windows.SECURITY_INFORMATION(windows.SACL_SECURITY_INFORMATION)
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, nil, acl)
}

// integrityLabel returns the last sub-authority of the mandatory label SID:
// 8192 = Medium, 12288 = High, 0 when the object has no label.
func integrityLabel(path string) (uint32, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return 0, err
	}
	if sacl == nil || sacl.AceCount == 0 {
		return 0, nil
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
			return 0, nil
		}
		off := 8 + 4*(count-1)
		return *(*uint32)(unsafe.Pointer(&raw[off])), nil
	}
	return 0, nil
}
