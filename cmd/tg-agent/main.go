// Command tg-agent is the protection agent that runs on every protected host.
//
// Subcommands:
//
//	tg-agent enroll --server URL --bootstrap TOKEN --ca CA.crt [--role protect]
//	tg-agent run    --state-dir DIR
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/enforcer"
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
  tg-agent run    [--state-dir DIR]
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
	})
	if err != nil {
		return err
	}
	fmt.Printf("enrolled as %s (role %s)\nstate written to %s\n", state.AgentID, state.Role, *stateDir)
	return nil
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

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	backend := fs.String("enforcer", "auto", "enforcement backend: auto, ebpf or observe")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	enf, err := enforcer.SelectKind(*backend, enforcer.Options{PublisherUIDs: state.PublisherUIDs})
	if err != nil {
		return err
	}
	capb := enf.Capability()
	if capb.Degraded {
		logger.Warn("running with degraded protection", "enforcer", capb.Kind, "reason", capb.Reason)
	}

	a, err := agent.New(state, enf, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}
