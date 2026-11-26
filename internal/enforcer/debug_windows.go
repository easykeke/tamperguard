//go:build windows

package enforcer

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DebugIntegrity is a diagnostics helper for the on-host test harness. It
// reports whether SeSecurityPrivilege can be enabled, what each step of the
// label write returns and what the read-back sees. It never panics and its
// return value is meant for a log line.
func DebugIntegrity(path, levelNameCfg string) string {
	level, ok := parseLevel(levelNameCfg)
	if !ok || level == levelUnknown {
		return fmt.Sprintf("bad level %q", levelNameCfg)
	}
	var b strings.Builder

	privErr := enablePrivilege("SeSecurityPrivilege")
	fmt.Fprintf(&b, "enablePrivilege=%v ", privErr)
	state, err := securityPrivilegeState()
	if err != nil {
		fmt.Fprintf(&b, "privQueryErr=%v ", err)
	} else {
		fmt.Fprintf(&b, "privState=%s ", state)
	}

	setErr := setIntegrity(path, level, false)
	fmt.Fprintf(&b, "setIntegrity=%v ", setErr)

	if got, rerr := integrityOf(path); rerr != nil {
		fmt.Fprintf(&b, "readbackErr=%v ", rerr)
	} else {
		fmt.Fprintf(&b, "readback=%s ", levelName(got))
	}

	sd, gerr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if gerr != nil {
		fmt.Fprintf(&b, "getSaclErr=%v", gerr)
	} else if sacl, _, serr := sd.SACL(); serr != nil {
		fmt.Fprintf(&b, "saclErr=%v", serr)
	} else if sacl == nil {
		b.WriteString("sacl=nil")
	} else {
		fmt.Fprintf(&b, "saclAces=%d", sacl.AceCount)
	}
	return b.String()
}

// securityPrivilegeState reports whether SeSecurityPrivilege is present and
// enabled in the current token.
func securityPrivilegeState() (string, error) {
	namePtr, err := windows.UTF16PtrFromString("SeSecurityPrivilege")
	if err != nil {
		return "", err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return "", err
	}
	tok := windows.GetCurrentProcessToken()
	var size uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &size)
	if size == 0 {
		return "unknown", nil
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], size, &size); err != nil {
		return "", err
	}
	type luidAndAttributes struct {
		Luid       windows.LUID
		Attributes uint32
	}
	type tokenPrivileges struct {
		Count      uint32
		Privileges [1]luidAndAttributes
	}
	tp := (*tokenPrivileges)(unsafe.Pointer(&buf[0]))
	items := unsafe.Slice(&tp.Privileges[0], tp.Count)
	for i := range items {
		if items[i].Luid == luid {
			if items[i].Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
				return "enabled", nil
			}
			return fmt.Sprintf("present(attrs=0x%x)", items[i].Attributes), nil
		}
	}
	return "absent", nil
}
