// Command tg-publish is the release agent. It polls the control plane for
// release requests assigned to it, hashes the source tree, obtains a
// manifest-bound token and writes the files.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/publish"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "sync":
		err = cmdSync(os.Args[2:])
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
	fmt.Fprint(os.Stderr, `TamperGuard release agent

  tg-publish run  [--state-dir DIR] [--verity]
  tg-publish sync --node NODE --source DIR --target DIR [--mode full|incremental]
                  [--delivery local|pull] [--note TEXT] [--timeout 5m]
`)
}

// cmdSync creates a release from the publisher host and waits for it to finish.
// This is the manual trigger path: no administrator request is needed.
func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	nodeID := fs.String("node", "", "target protect node id")
	source := fs.String("source", "", "source directory on this host")
	target := fs.String("target", "", "target directory on the protected node")
	mode := fs.String("mode", "full", "sync mode: full or incremental")
	delivery := fs.String("delivery", "pull", "delivery: pull (upload) or local (write target directly)")
	note := fs.String("note", "", "release note")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for completion")
	verity := fs.Bool("verity", false, "enable fs-verity on locally installed files")
	_ = fs.Parse(args)

	if *nodeID == "" || *source == "" || *target == "" {
		return fmt.Errorf("--node, --source and --target are required")
	}
	if *mode != "full" && *mode != "incremental" {
		return fmt.Errorf("--mode must be full or incremental")
	}
	if *delivery != "local" && *delivery != "pull" {
		return fmt.Errorf("--delivery must be local or pull")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	if state.Role != "publish" {
		return fmt.Errorf("this identity has role %q; enrol with --role publish", state.Role)
	}
	p, err := publish.New(state, logger, *verity)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return p.TriggerSync(ctx, publish.SyncOptions{
		NodeID:    *nodeID,
		SourceDir: *source,
		TargetDir: *target,
		Note:      *note,
		Mode:      *mode,
		Delivery:  *delivery,
	}, *timeout)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	verity := fs.Bool("verity", false, "enable fs-verity on the files of every locally installed release")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	if state.Role != "publish" {
		return fmt.Errorf("this identity has role %q; enrol with --role publish", state.Role)
	}
	p, err := publish.New(state, logger, *verity)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return p.Run(ctx)
}
