// tg-proxy is the web-layer integrity proxy: it snapshots a static site into a
// content-addressed store and serves only manifest entries, re-verifying the
// on-disk file for every request. If the file was modified, the trusted copy is
// served instead and a web.tamper-detected event is appended to the audit log.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/webproxy"
)

func main() {
	root := flag.String("root", "", "document root to protect")
	state := flag.String("state", "", "state directory holding the manifest and trusted blobs")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	upstream := flag.String("upstream", "", "forward unknown paths to this upstream (dynamic applications)")
	auditPath := flag.String("audit", "", "append tamper events as JSON lines to this file")
	snapshotOnly := flag.Bool("snapshot-only", false, "take a snapshot and exit")
	noSnapshot := flag.Bool("no-snapshot", false, "use the existing manifest instead of re-snapshotting")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *root == "" || *state == "" {
		fmt.Fprintln(os.Stderr, "usage: tg-proxy --root DIR --state DIR [--listen ADDR] [--upstream URL] [--audit FILE] [--snapshot-only] [--no-snapshot]")
		os.Exit(2)
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
	absState, err := filepath.Abs(*state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}

	var manifest *webproxy.Manifest
	if *noSnapshot {
		manifest, err = webproxy.LoadManifest(absState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: load manifest (run without --no-snapshot first): %v\n", err)
			os.Exit(2)
		}
		logger.Info("trusted manifest loaded", "files", len(manifest.Entries), "created", time.Unix(manifest.CreatedAt, 0).Format(time.RFC3339))
	} else {
		manifest, err = webproxy.Snapshot(absRoot, absState)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: snapshot:", err)
			os.Exit(1)
		}
		logger.Info("trusted snapshot created", "files", len(manifest.Entries), "state", absState)
	}
	if *snapshotOnly {
		fmt.Printf("snapshot: %d files, manifest=%s\n", len(manifest.Entries), webproxy.ManifestPath(absState))
		return
	}

	srv, err := webproxy.New(absRoot, absState, manifest, *upstream, *auditPath, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sd)
	}()

	logger.Info("web-layer integrity proxy listening",
		"addr", *listen, "root", absRoot, "files", len(manifest.Entries), "upstream", *upstream)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	logger.Info("proxy stopped")
}
