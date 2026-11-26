// Command tg-agent is the protection agent that runs on every protected host.
//
// Subcommands:
//
//	tg-agent enroll --server URL --bootstrap TOKEN --ca CA.crt [--role protect]
//	tg-agent run    --state-dir DIR
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/fsverity"
	"github.com/easykeke/tamperguard/internal/landlock"
	"github.com/easykeke/tamperguard/internal/selfcheck"
	"github.com/easykeke/tamperguard/internal/uninstall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		if runtime.GOOS == "windows" {
			fmt.Println("\n按回车退出…")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "probe":
		err = cmdProbe(os.Args[2:])
	case "landlock":
		err = cmdLandlock(os.Args[2:])
	case "verity":
		err = cmdVerity(os.Args[2:])
	case "selfcheck":
		err = cmdSelfcheck(os.Args[2:])
	case "ebpf-detach":
		err = cmdEBPFDetach()
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "unlock":
		err = cmdUnlock(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `TamperGuard protection agent

  tg-agent enroll --server URL --bootstrap TOKEN --ca FILE [--role protect] [--state-dir DIR]
  tg-agent run    [--state-dir DIR] [--enforcer auto|ebpf|fanotify|windows-acl|observe]
  tg-agent probe  [--state-dir DIR]
  tg-agent landlock [--allow-write DIRS] [--check] -- CMD [ARGS...]
  tg-agent verity  enable|digest|check PATH
  tg-agent selfcheck [--state-dir DIR] (verify the agent's own files)
  tg-agent ebpf-detach               (remove pinned LSM links; maintenance)
  tg-agent uninstall [--state-dir DIR] [--ticket CODE] [--reason TEXT] [--dry-run]
  tg-agent unlock [--state-dir DIR]   (Windows: restore inherited permissions)
`)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "https://127.0.0.1:8443", "control plane URL")
	bootstrap := fs.String("bootstrap", "", "one-time bootstrap token")
	role := fs.String("role", "protect", "protect or publish")
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	caFile := fs.String("ca", "", "CA certificate file")
	fingerprint := fs.String("ca-fingerprint", "", "CA certificate SHA-256 fingerprint")
	publishDir := fs.String("publish-dir", "", "default publish directory (publish role)")
	poll := fs.Int("poll", 15, "sync interval in seconds")
	publisherUIDs := fs.String("publisher-uids", "0", "comma-separated uids allowed to use a live release grant")
	publisherSIDs := fs.String("publisher-sids", "", "comma-separated Windows accounts/SIDs allowed to use a live grant")
	tpmAKPub := fs.String("tpm-ak-pub", "", "PEM file with the TPM attestation key public key (enables TPM quote verification)")
	tpmAutoAK := fs.Bool("tpm-auto-ak", false, "create an EK/AK on the TPM and register the AK public key automatically")
	tpmTCTI := fs.String("tpm-tcti", "", "TPM2 TCTI for --tpm-auto-ak, e.g. device:/dev/tpmrm0 or swtpm:host=127.0.0.1,port=2321")
	_ = fs.Parse(args)
	tpmPub := ""
	if *tpmAKPub != "" {
		raw, err := os.ReadFile(*tpmAKPub)
		if err != nil {
			return fmt.Errorf("read --tpm-ak-pub: %w", err)
		}
		tpmPub = string(raw)
	}
	akCtx := ""
	if *tpmAutoAK {
		ctxPath, pem, err := agent.ProvisionAK(*stateDir, *tpmTCTI)
		if err != nil {
			return fmt.Errorf("auto-provision TPM AK: %w", err)
		}
		akCtx, tpmPub = ctxPath, pem
		fmt.Printf("TPM AK provisioned: %s\n", ctxPath)
	}

	state, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		ServerURL:      *server,
		BootstrapToken: *bootstrap,
		Role:           *role,
		StateDir:       *stateDir,
		CAFile:         *caFile,
		CAFingerprint:  *fingerprint,
		PublishDir:     *publishDir,
		PollSeconds:    *poll,
		PublisherUIDs:  parseIntList(*publisherUIDs),
		PublisherSIDs:  parseStringList(*publisherSIDs),
		TPMAKPub:       tpmPub,
		TPMAKCtx:       akCtx,
		TPMTCTI:        *tpmTCTI,
	})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (role %s)\nstate written to %s\n", state.AgentID, state.Role, *stateDir)
	return nil
}

// cmdLandlock confines the given command with Landlock and execs it. This is
// the process self-protection layer: the web server runs inside a domain where
// the document root is read-only, so an RCE cannot rewrite content even though
// the file permissions would allow it.
func cmdLandlock(args []string) error {
	fs := flag.NewFlagSet("landlock", flag.ExitOnError)
	allow := fs.String("allow-write", "", "comma-separated directories the confined process may write")
	noDefaults := fs.Bool("no-defaults", false, "do not implicitly allow /tmp, /var/tmp and /dev/shm")
	check := fs.Bool("check", false, "print the Landlock ABI and exit")
	_ = fs.Parse(args)

	if *check {
		abi, err := landlock.ABI()
		if err != nil {
			return err
		}
		fmt.Printf("landlock ABI: %d\n", abi)
		return nil
	}
	var dirs []string
	if !*noDefaults {
		for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				dirs = append(dirs, d)
			}
		}
		// Device files are commonly opened for writing by shells, runtimes and
		// logging libraries; allow the harmless ones explicitly instead of the
		// whole /dev tree (which contains block devices).
		for _, f := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"} {
			if _, err := os.Stat(f); err == nil {
				dirs = append(dirs, f)
			}
		}
	}
	dirs = append(dirs, parseStringList(*allow)...)
	command := fs.Args()
	if len(command) == 0 {
		return errors.New("landlock: no command given (usage: tg-agent landlock [flags] -- command args...)")
	}
	cfg := landlock.Config{WritableDirs: dirs}
	if err := landlock.Exec(cfg, command, os.Environ()); err != nil {
		return fmt.Errorf("landlock: %w", err)
	}
	return nil
}

// cmdSelfcheck verifies the agent binary, unit and config against the stored
// baseline and exits non-zero on a mismatch.
func cmdSelfcheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	_ = fs.Parse(args)
	baseline := filepath.Join(*stateDir, "selfcheck.json")
	m, err := selfcheck.Load(baseline)
	if err != nil {
		return fmt.Errorf("selfcheck: no baseline at %s (the agent creates it on first start): %w", baseline, err)
	}
	diffs, err := selfcheck.Compare(m)
	if err != nil {
		return err
	}
	if len(diffs) == 0 {
		fmt.Printf("selfcheck: OK (%d files match)\n", len(m.Files))
		return nil
	}
	for _, d := range diffs {
		fmt.Println("selfcheck: CHANGED", d.String())
	}
	return fmt.Errorf("selfcheck: %d file(s) changed", len(diffs))
}

// cmdEBPFDetach removes the pinned LSM links. Stopping the service does not
// remove them on purpose (a stopped agent must not silently disable
// protection), so maintenance uses this command.
func cmdEBPFDetach() error {
	n, err := enforcer.DetachPinned()
	if err != nil {
		return err
	}
	fmt.Printf("detached %d pinned LSM links\n", n)
	return nil
}

// cmdUninstall removes the agent. There are exactly two ways to get here:
// an administrator approves the request and hands back a challenge code, or the
// management plane pushes a ticket to the running agent. A local decision alone
// never uninstalls the agent.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	reason := fs.String("reason", "", "why the agent is being removed (shown to the administrator)")
	ticketCode := fs.String("ticket", "", "challenge code returned after management approval; skips the request/poll flow")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for an administrator to approve")
	dryRun := fs.Bool("dry-run", false, "verify the ticket and stop (remove nothing)")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	client, err := agent.NewClient(state)
	if err != nil {
		return err
	}

	ticket := *ticketCode
	nonce := ""
	if ticket == "" {
		nonce, err = uninstall.Nonce()
		if err != nil {
			return err
		}
		id, err := client.RequestUninstall(ctx, nonce, *reason)
		if err != nil {
			return err
		}
		fmt.Printf("request_id=%s\n", id)
		fmt.Println("waiting for an administrator to approve the uninstall request...")
		deadline := time.Now().Add(*timeout)
		for ticket == "" {
			if time.Now().After(deadline) {
				return errors.New("uninstall: approval timed out; the request is still pending on the control plane")
			}
			st, err := client.GetUninstallStatus(ctx, id)
			if err != nil {
				return err
			}
			switch st.Status {
			case uninstall.StatusApproved:
				ticket = st.Ticket
			case uninstall.StatusDenied:
				return errors.New("uninstall: request denied by the administrator")
			default:
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
				}
			}
		}
	}

	tk, err := client.VerifyUninstallTicket(ticket, state.AgentID, nonce)
	if err != nil {
		return fmt.Errorf("uninstall: challenge code rejected: %w", err)
	}
	fmt.Printf("challenge verified: request=%s expires=%s\n", tk.RequestID, time.Unix(tk.ExpiresAt, 0).Format(time.RFC3339))

	exe, _ := os.Executable()
	unit, service := uninstall.DefaultSystemTargets()
	opts := uninstall.Options{
		StateDir:    *stateDir,
		BinaryPath:  exe,
		UnitPath:    unit,
		ServiceName: service,
		DryRun:      *dryRun,
	}
	actions, perr := uninstall.Perform(ctx, opts)
	for _, a := range actions {
		fmt.Println(" -", a)
	}
	if *dryRun {
		fmt.Println("dry-run: no files were removed")
		return nil
	}
	if perr != nil {
		return perr
	}
	fmt.Println("agent uninstalled")
	return nil
}

// cmdVerity exposes fs-verity operations for operators and tests.
func cmdVerity(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: tg-agent verity enable|digest|check PATH")
	}
	action, path := args[0], args[1]
	switch action {
	case "enable":
		if err := fsverity.Enable(path); err != nil {
			return err
		}
		fmt.Printf("fs-verity enabled: %s\n", path)
		return nil
	case "digest":
		digest, err := fsverity.Digest(path)
		if err != nil {
			return err
		}
		fmt.Println(digest)
		return nil
	case "check":
		ok, err := fsverity.IsVerity(path)
		if err != nil {
			return err
		}
		fmt.Printf("verity=%v\n", ok)
		return nil
	default:
		return fmt.Errorf("unknown verity action %q (want enable, digest or check)", action)
	}
}

// cmdUnlock restores inherited permissions on Windows (explicit operator
// action; the agent never unlocks on shutdown or crash).
func cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	_ = fs.Parse(args)
	if err := enforcer.Unlock(*stateDir); err != nil {
		return err
	}
	fmt.Println("inherited permissions restored for previously protected paths")
	return nil
}

func parseStringList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseIntList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		out = []int{0}
	}
	return out
}

// cmdProbe prints which enforcement backend this host supports and why the
// stronger ones are unavailable. Run it before rolling an agent out.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory (baseline location)")
	_ = fs.Parse(args)
	rep := enforcer.Probe(*stateDir)
	fmt.Print(enforcer.FormatProbe(rep))
	if hint := enforcer.SecurityFSMountHint(); hint != "" {
		fmt.Printf("securityfs    : %s\n", hint)
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	backend := fs.String("enforcer", "auto", "enforcement backend: auto, ebpf, fanotify or observe")
	autoUpgrade := fs.Bool("auto-upgrade", true, "accept signed agent updates")
	upgradeInterval := fs.Duration("upgrade-interval", 6*time.Hour, "how often to check for updates")
	raspEnabled := fs.Bool("rasp", true, "serve the application-layer probe socket")
	raspSocket := fs.String("rasp-socket", "", "override the probe socket path")
	integrityLevel := fs.String("integrity-level", "system", "Windows: mandatory label for protected paths (system needs a SYSTEM service; high/medium/off)")
	allowAdmins := fs.Bool("windows-allow-admins", false, "Windows: keep write access for the Administrators group (weakens protection; strict by default)")
	verity := fs.Bool("verity", false, "enable fs-verity on files installed by pull deliveries (read-only + verified reads)")
	tpmAK := fs.String("tpm-ak-ctx", "", "TPM attestation key context for quote (empty disables TPM attestation)")
	tpmTCTI := fs.String("tpm-tcti", "", "TPM2 TCTI, e.g. device:/dev/tpmrm0 or swtpm:host=127.0.0.1,port=2321")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	if *tpmAK == "" {
		*tpmAK = state.TPMAKCtx
	}
	if *tpmTCTI == "" {
		*tpmTCTI = state.TPMTCTI
	}
	enf, err := enforcer.SelectKind(*backend, enforcer.Options{
		PublisherUIDs:  state.PublisherUIDs,
		PublisherSIDs:  state.PublisherSIDs,
		StateDir:       *stateDir,
		IntegrityLevel: *integrityLevel,
		AllowAdmins:    *allowAdmins,
	})
	if err != nil {
		return err
	}
	capb := enf.Capability()
	if capb.Degraded {
		logger.Warn("running with degraded protection", "enforcer", capb.Kind, "reason", capb.Reason)
	}

	a, err := agent.New(state, enf, agent.Options{
		TPMQuoteAK:      *tpmAK,
		TPMQuoteTCTI:    *tpmTCTI,
		Logger:          logger,
		AutoUpgrade:     *autoUpgrade,
		UpgradeInterval: *upgradeInterval,
		RASP:            *raspEnabled,
		RASPSocket:      *raspSocket,
		Verity:          *verity,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		if errors.Is(err, agent.ErrUpgradeStaged) {
			logger.Info("agent binary upgraded; service manager should restart the process")
			return nil
		}
		return err
	}
	return nil
}
