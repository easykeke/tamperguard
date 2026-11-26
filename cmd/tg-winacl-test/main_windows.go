//go:build windows

// tg-winacl-test proves the Windows enforcement semantics on a real host.
//
// Two modes, because Windows does not allow a process to label an object above
// its own integrity level:
//
//	admin  (default, run elevated): strict DACL denies administrator writes,
//	       grant/revoke work, bypass is reverted only if the agent can write
//	       (a High process cannot write a System label, so MIC is limited here)
//	system (run as a SYSTEM scheduled task): the agent can apply the System
//	       label and restore files, so this mode verifies the label application
//	       and the self-heal path end to end
//
// The "elevated administrator is denied by the System label" case is verified by
// .test-win/run-mic-demo.ps1, which applies the label from a SYSTEM task and then
// writes from an administrator session.
//
// Every step is written to stdout and --log (flushed), with a 120s watchdog that
// dumps goroutines so a hang is diagnosable.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/token"
)

var (
	failures int
	logFile  *os.File
)

func logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	fmt.Println(line)
	if logFile != nil {
		_, _ = logFile.WriteString(line + "\n")
		_ = logFile.Sync()
	}
}

func check(name string, ok bool, detail string) {
	if ok {
		logf("  [ok]   %s", name)
		return
	}
	failures++
	if detail != "" {
		logf("  [FAIL] %s (%s)", name, detail)
	} else {
		logf("  [FAIL] %s", name)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%s %v: %v (%s)", name, args, err, string(out))
	}
	return string(out)
}

func logSecurityState(label, path string) {
	logf("  [state] %s", label)
	for _, line := range strings.Split(strings.ReplaceAll(run("icacls", path), "\r", ""), "\n") {
		if strings.TrimSpace(line) != "" {
			logf("          %s", line)
		}
	}
}

// tokenLevel reads the integrity level of the current process token.
func tokenLevel() string {
	tok := windows.GetCurrentProcessToken()
	var size uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "unknown"
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return "unknown"
	}
	return fmt.Sprintf("raw=% x", buf[:16])
}

func main() {
	dir := flag.String("dir", "", "test root directory (created and removed by the test)")
	logPath := flag.String("log", "", "append a copy of the output to this file")
	mode := flag.String("mode", "admin", "admin (elevated) or system (SYSTEM task)")
	flag.Parse()

	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Println("ERROR: open log:", err)
			os.Exit(2)
		}
		logFile = f
		defer f.Close()
	}
	logf("=== tg-winacl-test start %s mode=%s ===", time.Now().Format(time.RFC3339), *mode)

	time.AfterFunc(120*time.Second, func() {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		logf("WATCHDOG: exceeded 120s, dumping goroutines:\n%s", buf[:n])
		os.Exit(3)
	})

	if !windows.GetCurrentProcessToken().IsElevated() {
		logf("ERROR: this test must run elevated")
		os.Exit(2)
	}
	if *dir == "" {
		logf("ERROR: --dir is required")
		os.Exit(2)
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		logf("ERROR: abs: %v", err)
		os.Exit(2)
	}
	stateDir := filepath.Join(root, "state")

	if err := os.RemoveAll(root); err != nil {
		logf("cleanup: previous sandbox is locked, restoring: %v", err)
		if _, statErr := os.Stat(stateDir); statErr == nil {
			_ = enforcer.Unlock(stateDir)
		}
		_ = run("takeown", "/F", root, "/R", "/D", "Y")
		_ = run("icacls", root, "/reset", "/T", "/C")
		if err := os.RemoveAll(root); err != nil {
			logf("ERROR: cannot remove previous sandbox: %v", err)
			os.Exit(2)
		}
	}
	site := filepath.Join(root, "site")
	scratch := filepath.Join(root, "scratch")
	for _, d := range []string{site, scratch} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			logf("ERROR: create dir: %v", err)
			os.Exit(2)
		}
	}
	index := filepath.Join(site, "index.html")
	if err := os.WriteFile(index, []byte("original"), 0o644); err != nil {
		logf("ERROR: seed file: %v", err)
		os.Exit(2)
	}
	_ = os.Setenv("TG_WIN_SCAN_SECONDS", "2")

	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		logf("ERROR: current user SID: %v", err)
		os.Exit(2)
	}
	publisher := u.User.Sid.String()
	level := "high"
	if *mode == "system" {
		level = "system"
	}
	logf("publisher account: %s", publisher)
	logf("requested integrity level: %s (token: %s)", level, tokenLevel())

	eng, err := enforcer.SelectKind("windows-acl", enforcer.Options{
		PublisherSIDs:  []string{publisher},
		StateDir:       stateDir,
		IntegrityLevel: level,
	})
	if err != nil {
		logf("ERROR: start windows-acl backend: %v", err)
		os.Exit(2)
	}
	defer eng.Close()

	siteNorm, ok := token.NormalizePath(site)
	if !ok {
		logf("ERROR: normalize test path")
		os.Exit(2)
	}
	rt := enforcer.Runtime{Policy: &policy.Snapshot{Policy: policy.Policy{
		Name:  "win-acl-test",
		Paths: []policy.PathRule{{Path: siteNorm, Recursive: true, Mode: policy.ModeEnforce}},
	}}}

	logf("\n== step: apply policy ==")
	if err := eng.Update(rt); err != nil {
		logf("ERROR: apply policy: %v", err)
		os.Exit(2)
	}
	check("enforcer reports no health errors", eng.Health() == nil, errText(eng.Health()))
	capb := eng.Capability()
	logf("enforcer=%s degraded=%v", capb.Kind, capb.Degraded)
	logf("reason=%s", capb.Reason)
	logSecurityState("protected tree after apply", site)

	if *mode == "system" {
		runSystemMode(eng, index, scratch, site, &rt)
	} else {
		runAdminMode(eng, index, scratch, site, &rt)
	}

	logf("\n== cleanup ==")
	if uerr := enforcer.Unlock(stateDir); uerr != nil {
		check("unlock restores inherited permissions", false, errText(uerr))
	} else {
		check("unlock restores inherited permissions", true, "")
	}
	lerr := os.WriteFile(index, []byte("after-unlock"), 0o644)
	check("maintenance write allowed after unlock", lerr == nil, errText(lerr))
	_ = run("icacls", root, "/reset", "/T", "/C")
	if err := os.RemoveAll(root); err != nil {
		logf("  note: could not remove test root: %v", err)
	} else {
		logf("  [ok]   test root removed")
	}

	logf("")
	if failures > 0 {
		logf("RESULT: FAILED (%d checks)", failures)
		os.Exit(1)
	}
	logf("RESULT: PASS")
}

// runAdminMode covers the strict DACL, the release window and the bypass
// simulation. MIC is limited here: a High process cannot write a System label.
func runAdminMode(eng enforcer.Enforcer, index, scratch, site string, rt *enforcer.Runtime) {
	logf("\n== protected tree, elevated administrator ==")
	err := os.WriteFile(index, []byte("evil"), 0o644)
	check("overwrite existing file denied", err != nil, errText(err))
	if data, rerr := os.ReadFile(index); rerr == nil {
		check("content unchanged", string(data) == "original", string(data))
	}
	err = os.WriteFile(filepath.Join(site, "new.html"), []byte("evil"), 0o644)
	check("create new file denied", err != nil, errText(err))
	if _, statErr := os.Stat(filepath.Join(site, "new.html")); statErr == nil {
		check("new file absent after denial", false, "file exists")
	}
	data, rerr := os.ReadFile(index)
	check("read still allowed", rerr == nil && string(data) == "original", errText(rerr))

	logf("\n== paths outside the policy ==")
	err = os.WriteFile(filepath.Join(scratch, "ok.txt"), []byte("ok"), 0o644)
	check("write outside policy allowed", err == nil, errText(err))

	logf("\n== release grant window ==")
	rt.Grants = []policy.Grant{{Paths: []string{normalized(site)}, ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}}
	check("grant applied", eng.Update(*rt) == nil, "")
	err = os.WriteFile(index, []byte("published"), 0o644)
	check("authorised publisher write during grant", err == nil, errText(err))

	logf("\n== revocation ==")
	rt.Grants = nil
	check("revocation applied", eng.Update(*rt) == nil, "")
	err = os.WriteFile(index, []byte("evil-after-revoke"), 0o644)
	check("write denied again after revocation", err != nil, errText(err))

	logf("\n== self-heal after an administrator bypass ==")
	_ = run("icacls", index, "/setintegritylevel", "Medium")
	_ = run("icacls", index, "/setowner", "Administrators", "/C")
	_ = run("icacls", index, "/grant", os.Getenv("USERNAME")+":F")
	bypass := os.WriteFile(index, []byte("evil-bypass"), 0o644)
	check("administrator bypass write succeeded (expected without a driver)", bypass == nil, errText(bypass))
	if bypass == nil {
		waitRestored(eng, index, "published", 25*time.Second)
	}
}

// runSystemMode covers what only a SYSTEM agent can do: apply the System label
// and restore files through the self-heal loop.
func runSystemMode(eng enforcer.Enforcer, index, scratch, site string, rt *enforcer.Runtime) {
	check("System label applied", eng.Health() == nil, errText(eng.Health()))
	logSecurityState("label check", site)

	logf("\n== SYSTEM agent: tamper is reverted by self-heal ==")
	if err := os.WriteFile(index, []byte("evil-idle"), 0o644); err != nil {
		check("SYSTEM can write (needed for restore)", false, errText(err))
		return
	}
	check("SYSTEM can write (needed for restore)", true, "")
	waitRestored(eng, index, "original", 25*time.Second)

	logf("\n== release grant window (label downgraded) ==")
	rt.Grants = []policy.Grant{{Paths: []string{normalized(site)}, ExpiresAt: time.Now().Add(10 * time.Minute).Unix()}}
	check("grant applied", eng.Update(*rt) == nil, "")
	check("grant health (expected Medium label)", eng.Health() == nil, errText(eng.Health()))
	if err := os.WriteFile(index, []byte("published"), 0o644); err != nil {
		check("publisher write during grant", false, errText(err))
	}

	logf("\n== revocation (back to idle level) ==")
	rt.Grants = nil
	check("revocation applied", eng.Update(*rt) == nil, "")
	check("revocation health (expected System label)", eng.Health() == nil, errText(eng.Health()))

	logf("\n== paths outside the policy ==")
	err := os.WriteFile(filepath.Join(scratch, "ok.txt"), []byte("ok"), 0o644)
	check("write outside policy allowed", err == nil, errText(err))
}

func waitRestored(eng enforcer.Enforcer, path, want string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if data, err := os.ReadFile(path); err == nil && string(data) == want {
			check("self-heal restored the file from baseline", true, "")
			drainEvents(eng)
			return
		}
	}
	check("self-heal restored the file from baseline", false, "content was not restored")
	drainEvents(eng)
}

func drainEvents(eng enforcer.Enforcer) {
	saw := false
	timer := time.After(5 * time.Second)
drain:
	for {
		select {
		case ev := <-eng.Events():
			logf("  [event] %s", ev.Kind)
			if ev.Kind == audit.KindTamperRestored {
				saw = true
				break drain
			}
		case <-timer:
			break drain
		}
	}
	check("tamper.restored audit event emitted", saw, "no event observed")
}

func normalized(p string) string {
	n, ok := token.NormalizePath(p)
	if !ok {
		return p
	}
	return n
}
