// Command tg-agent is the protection agent that runs on every protected host.
//
// Subcommands:
//
//	tg-agent enroll --server URL --bootstrap TOKEN --ca CA.crt [--role protect]
//	tg-agent run    --state-dir DIR
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/landlock"
)

func main() {
	if len(os.Args) < 2 {
		usage()
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
	_ = fs.Parse(args)

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
	integrity := fs.Bool("integrity", true, "Windows: also label protected paths High (NO_WRITE_UP), needs SeSecurityPrivilege")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	enf, err := enforcer.SelectKind(*backend, enforcer.Options{
		PublisherUIDs:  state.PublisherUIDs,
		PublisherSIDs:  state.PublisherSIDs,
		StateDir:       *stateDir,
		IntegrityLevel: *integrity,
	})
	if err != nil {
		return err
	}
	capb := enf.Capability()
	if capb.Degraded {
		logger.Warn("running with degraded protection", "enforcer", capb.Kind, "reason", capb.Reason)
	}

	a, err := agent.New(state, enf, agent.Options{
		Logger:          logger,
		AutoUpgrade:     *autoUpgrade,
		UpgradeInterval: *upgradeInterval,
		RASP:            *raspEnabled,
		RASPSocket:      *raspSocket,
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
