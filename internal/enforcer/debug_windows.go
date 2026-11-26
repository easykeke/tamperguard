//go:build windows

package enforcer

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DebugIntegrity is a diagnostics helper for the on-host test harness. It
// compares the label of known system objects with the target, tries to write
// the requested label, and prints the raw SDDL and icacls view afterwards. The
// returned string is meant for a single log line.
func DebugIntegrity(path, levelNameCfg string) string {
	level, ok := parseLevel(levelNameCfg)
	if !ok || level == levelUnknown {
		return fmt.Sprintf("bad level %q", levelNameCfg)
	}
	var b strings.Builder

	privErr := enablePrivilege("SeSecurityPrivilege")
	state, qerr := securityPrivilegeState()
	fmt.Fprintf(&b, "privilege=%v/%s(qerr=%v)", privErr, state, qerr)

	// Known-label controls: if these read as unknown while icacls shows a label,
	// the read path is broken rather than the write path.
	describeLabel(&b, "kernel32", `C:\Windows\System32\kernel32.dll`)
	describeLabel(&b, "windows", `C:\Windows`)
	describeLabel(&b, "programdata", `C:\ProgramData`)
	describeLabel(&b, "target-before", path)

	setErr := setIntegrity(path, level, false)
	fmt.Fprintf(&b, " | set=%v", setErr)

	if out, err := exec.Command("icacls.exe", path).CombinedOutput(); err != nil {
		fmt.Fprintf(&b, " | icacls-error=%v", err)
	} else {
		fmt.Fprintf(&b, " | icacls=[%s]", firstNonEmptyLine(string(out)))
	}

	describeLabel(&b, "target-after", path)
	if sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION); err != nil {
		fmt.Fprintf(&b, " | sddlErr=%v", err)
	} else if s := sd.String(); len(s) > 0 {
		fmt.Fprintf(&b, " | sddl=%s", truncate(s, 240))
	}
	return b.String()
}

// describeLabel renders "tag=low(aces=1)" for one path.
func describeLabel(b *strings.Builder, tag, path string) {
	level, err := integrityOf(path)
	aces, saclErr := saclAceCount(path)
	fmt.Fprintf(b, " | %s=%s(aces=%d,types=%s,readErr=%v,saclErr=%v)", tag, levelName(level), aces, saclAceTypes(path), err, saclErr)
}

// saclAceTypes lists ACE types in the SACL so a parser mismatch is visible.
func saclAceTypes(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return "err:" + err.Error()
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return "err:" + err.Error()
	}
	if sacl == nil {
		return "nil"
	}
	var b strings.Builder
	for i := 0; i < int(sacl.AceCount) && i < 3; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(sacl, uint32(i), &ace); err != nil {
			b.WriteString("getace-err")
			break
		}
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "0x%x", ace.Header.AceType)
	}
	if b.Len() == 0 {
		b.WriteString("empty")
	}
	return b.String()
}

func saclAceCount(path string) (int, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION)
	if err != nil {
		return -1, err
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return -1, err
	}
	if sacl == nil {
		return 0, nil
	}
	return int(sacl.AceCount), nil
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
