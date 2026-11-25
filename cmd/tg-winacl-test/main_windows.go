//go:build windows

// tg-winacl-test proves the Windows enforcement semantics on a real host:
//
//  1. an elevated administrator cannot overwrite or create files in a protected
//     directory (strict DACL + System integrity label, no driver involved);
//  2. reads and writes outside the policy still work;
//  3. during a live release grant the authorised publisher account can write;
//  4. after revocation the same account is denied again;
//  5. `unlock` restores inherited permissions so the operator can maintain the
//     tree afterwards.
//
// It must run elevated (the agent needs SeSecurityPrivilege for the SACL) and
// writes a PASS/FAIL table to stdout.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/token"
)

var failures int

func check(name string, ok bool, detail string) {
	if ok {
		fmt.Printf("  [ok]   %s\n", name)
		return
	}
	failures++
	if detail != "" {
		fmt.Printf("  [FAIL] %s (%s)\n", name, detail)
	} else {
		fmt.Printf("  [FAIL] %s\n", name)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func main() {
	dir := flag.String("dir", "", "test root directory (created and removed by the test)")
	flag.Parse()

	if !windows.GetCurrentProcessToken().IsElevated() {
		fmt.Println("ERROR: this test must run elevated (Administrator or SYSTEM)")
		fmt.Println("       right-click PowerShell -> Run as administrator, then re-run")
		os.Exit(2)
	}
	if *dir == "" {
		fmt.Println("ERROR: --dir is required")
		os.Exit(2)
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}
	if err := os.RemoveAll(root); err != nil {
		fmt.Println("ERROR: clean test root:", err)
		os.Exit(2)
	}
	site := filepath.Join(root, "site")
	scratch := filepath.Join(root, "scratch")
	for _, d := range []string{site, scratch} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fmt.Println("ERROR: create dir:", err)
			os.Exit(2)
		}
	}
	index := filepath.Join(site, "index.html")
	if err := os.WriteFile(index, []byte("original"), 0o644); err != nil {
		fmt.Println("ERROR: seed file:", err)
		os.Exit(2)
	}
	stateDir := filepath.Join(root, "state")

	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		fmt.Println("ERROR: current user SID:", err)
		os.Exit(2)
	}
	publisher := u.User.Sid.String()

	eng, err := enforcer.SelectKind("windows-acl", enforcer.Options{
		PublisherSIDs:  []string{publisher},
		StateDir:       stateDir,
		IntegrityLevel: true,
	})
	if err != nil {
		fmt.Println("ERROR: start windows-acl backend:", err)
		os.Exit(2)
	}
	defer eng.Close()

	siteNorm, ok := token.NormalizePath(site)
	if !ok {
		fmt.Println("ERROR: normalize test path")
		os.Exit(2)
	}
	snap := &policy.Snapshot{Policy: policy.Policy{
		Name:  "win-acl-test",
		Paths: []policy.PathRule{{Path: siteNorm, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	rt := enforcer.Runtime{Policy: snap}
	if err := eng.Update(rt); err != nil {
		fmt.Println("ERROR: apply policy:", err)
		os.Exit(2)
	}
	capb := eng.Capability()
	fmt.Printf("enforcer=%s degraded=%v\n%s\n\n", capb.Kind, capb.Degraded, capb.Reason)

	fmt.Println("== protected tree, elevated administrator ==")
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

	fmt.Println("\n== paths outside the policy ==")
	err = os.WriteFile(filepath.Join(scratch, "ok.txt"), []byte("ok"), 0o644)
	check("write outside policy allowed", err == nil, errText(err))

	fmt.Println("\n== release grant window ==")
	rt.Grants = []policy.Grant{{
		Paths:     []string{siteNorm},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}}
	if uerr := eng.Update(rt); uerr != nil {
		// A non-SYSTEM agent (High integrity) cannot lower a System label;
		// report it instead of failing silently.
		check("grant applied (agent must run as SYSTEM to lower the label)", false, errText(uerr))
	} else {
		check("grant applied", true, "")
		err = os.WriteFile(index, []byte("published"), 0o644)
		check("authorised publisher write during grant", err == nil, errText(err))
	}

	fmt.Println("\n== revocation ==")
	rt.Grants = nil
	if uerr := eng.Update(rt); uerr != nil {
		check("revocation applied", false, errText(uerr))
	}
	err = os.WriteFile(index, []byte("evil-after-revoke"), 0o644)
	check("write denied again after revocation", err != nil, errText(err))

	fmt.Println("\n== cleanup ==")
	if uerr := enforcer.Unlock(stateDir); uerr != nil {
		check("unlock restores inherited permissions", false, errText(uerr))
	} else {
		check("unlock restores inherited permissions", true, "")
		lerr := os.WriteFile(index, []byte("after-unlock"), 0o644)
		check("maintenance write allowed after unlock", lerr == nil, errText(lerr))
	}
	if err := os.RemoveAll(root); err != nil {
		fmt.Println("  note: could not remove test root:", err)
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("RESULT: FAILED (%d checks)\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS")
}
