//go:build windows

// tg-winacl-test proves the Windows enforcement semantics on a real host:
//
//  1. an elevated administrator cannot overwrite or create files in a protected
//     directory (strict DACL + System integrity label, no driver involved);
//  2. reads and writes outside the policy still work;
//  3. during a live release grant the authorised publisher account can write;
//  4. after revocation the same account is denied again;
//  5. an administrator bypass (relabel + take ownership) is reverted by the
//     content baseline self-heal and recorded as tamper.restored;
//  6. `unlock` restores inherited permissions so the operator can maintain the
//     tree afterwards.
//
// Every step is written to both stdout and --log, with an explicit flush, and a
// watchdog dumps all goroutine stacks if the run exceeds two minutes. That makes
// a hang or crash diagnosable even when the console is closed.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// logSecurityState records the raw security state so a failure is diagnosable.
func logSecurityState(label, path string) {
	logf("  [state] %s", label)
	out := run("icacls", path)
	for _, line := range splitLines(out) {
		logf("          %s", line)
	}
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		if r == '\r' {
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func main() {
	dir := flag.String("dir", "", "test root directory (created and removed by the test)")
	logPath := flag.String("log", "", "append a copy of the output to this file")
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
	logf("=== tg-winacl-test start %s ===", time.Now().Format(time.RFC3339))

	// Watchdog: never hang silently.
	time.AfterFunc(120*time.Second, func() {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		logf("WATCHDOG: exceeded 120s, dumping goroutines:\n%s", buf[:n])
		os.Exit(3)
	})

	if !windows.GetCurrentProcessToken().IsElevated() {
		logf("ERROR: this test must run elevated (Administrator or SYSTEM)")
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

	// Clean a previous (possibly locked) sandbox: unlock, take ownership, reset
	// inherited permissions, then remove it.
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
	// Fast scanner for the test only.
	_ = os.Setenv("TG_WIN_SCAN_SECONDS", "2")

	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		logf("ERROR: current user SID: %v", err)
		os.Exit(2)
	}
	publisher := u.User.Sid.String()
	logf("publisher account (allowed during grant): %s", publisher)

	eng, err := enforcer.SelectKind("windows-acl", enforcer.Options{
		PublisherSIDs: []string{publisher},
		StateDir:      stateDir,
		// The harness runs as an elevated administrator (High integrity), and
		// Windows does not allow labelling objects above the caller's level. A
		// System label therefore needs a SYSTEM agent; the "admin write denied
		// by MIC" case is covered by run-mic-demo.ps1, which uses a SYSTEM
		// scheduled task. Here High still proves DACL denial, grants and the
		// self-heal path.
		IntegrityLevel: "high",
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
	snap := &policy.Snapshot{Policy: policy.Policy{
		Name:  "win-acl-test",
		Paths: []policy.PathRule{{Path: siteNorm, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	rt := enforcer.Runtime{Policy: snap}

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

	logf("\n== protected tree, elevated administrator ==")
	err = os.WriteFile(index, []byte("evil"), 0o644)
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
	rt.Grants = []policy.Grant{{
		Paths:     []string{siteNorm},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}}
	if uerr := eng.Update(rt); uerr != nil {
		check("grant applied", false, errText(uerr))
	} else {
		check("grant applied", eng.Health() == nil, errText(eng.Health()))
	}
	logSecurityState("protected tree during grant", site)
	err = os.WriteFile(index, []byte("published"), 0o644)
	check("authorised publisher write during grant", err == nil, errText(err))

	logf("\n== revocation ==")
	rt.Grants = nil
	if uerr := eng.Update(rt); uerr != nil {
		check("revocation applied", false, errText(uerr))
	} else {
		check("revocation applied", eng.Health() == nil, errText(eng.Health()))
	}
	err = os.WriteFile(index, []byte("evil-after-revoke"), 0o644)
	check("write denied again after revocation", err != nil, errText(err))

	logf("\n== self-heal after an administrator bypass ==")
	expected := "original"
	if data, rerr := os.ReadFile(index); rerr == nil {
		expected = string(data)
	}
	logf("baseline content before bypass: %q", expected)
	// Simulate what an administrator can still do: relabel the file, take
	// ownership and grant write. The scanner must revert the change.
	_ = run("icacls", index, "/setintegritylevel", "Medium")
	_ = run("icacls", index, "/setowner", "Administrators", "/C")
	_ = run("icacls", index, "/grant", os.Getenv("USERNAME")+":F")
	bypass := os.WriteFile(index, []byte("evil-bypass"), 0o644)
	check("administrator bypass write succeeded (expected without a driver)", bypass == nil, errText(bypass))

	restored := false
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if data, rerr := os.ReadFile(index); rerr == nil && string(data) == expected {
			restored = true
			break
		}
	}
	check("self-heal restored the file from baseline", restored, "content was not restored")

	sawEvent := false
	evTimer := time.After(5 * time.Second)
drain:
	for {
		select {
		case ev := <-eng.Events():
			logf("  [event] %s %s %s", ev.Kind, ev.Path, ev.Reason)
			if ev.Kind == audit.KindTamperRestored {
				sawEvent = true
				break drain
			}
		case <-evTimer:
			break drain
		}
	}
	check("tamper.restored audit event emitted", sawEvent, "no event observed")

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
