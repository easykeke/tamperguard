// tg-proxy is the web-layer integrity proxy: it serves a static site from a
// trusted, content-addressed snapshot and re-verifies the on-disk file for every
// request. If the file was modified, the trusted copy is served instead and a
// web.tamper-detected event is appended to the audit log.
//
// Two ways to establish the trusted snapshot:
//
//  1. --sync: fetch the control-plane-signed site manifest for this node over
//     mTLS, download every file from the control plane, verify its hash and store
//     it. The local disk is not trusted at all in this mode.
//  2. local snapshot (default): trust the current document root once. Use it only
//     when there is no control plane or right after a verified release.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/release"
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
	syncSigned := flag.Bool("sync", false, "fetch the signed manifest and artifacts from the control plane")
	agentState := flag.String("agent-state", "", "protect agent state directory (for --sync and signature re-verification)")
	requireSigned := flag.Bool("require-signed", false, "refuse to serve a manifest that is not control-plane signed")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *root == "" || *state == "" {
		fmt.Fprintln(os.Stderr, "usage: tg-proxy --root DIR --state DIR [--listen ADDR] [--upstream URL] [--audit FILE] [--snapshot-only] [--no-snapshot] [--sync --agent-state DIR] [--require-signed]")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var manifest *webproxy.Manifest
	switch {
	case *syncSigned:
		if *agentState == "" {
			fmt.Fprintln(os.Stderr, "ERROR: --sync requires --agent-state")
			os.Exit(2)
		}
		manifest, err = syncFromControlPlane(ctx, *agentState, absState, logger)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: sync:", err)
			os.Exit(1)
		}
		logger.Info("signed manifest synced", "files", len(manifest.Entries), "release", manifest.ReleaseID)
	case *noSnapshot:
		manifest, err = webproxy.LoadManifest(absState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: load manifest (run without --no-snapshot first): %v\n", err)
			os.Exit(2)
		}
		logger.Info("trusted manifest loaded", "files", len(manifest.Entries),
			"created", time.Unix(manifest.CreatedAt, 0).Format(time.RFC3339))
	default:
		manifest, err = webproxy.Snapshot(absRoot, absState)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: snapshot:", err)
			os.Exit(1)
		}
		logger.Info("trusted snapshot created", "files", len(manifest.Entries), "state", absState)
	}

	if *requireSigned {
		if !manifest.Signed() {
			fmt.Fprintln(os.Stderr, "ERROR: --require-signed is set but the manifest has no control-plane signature")
			os.Exit(2)
		}
		if *agentState != "" {
			if err := verifyLocalManifest(manifest, *agentState); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR: manifest signature does not verify:", err)
				os.Exit(2)
			}
			logger.Info("manifest signature verified", "release", manifest.ReleaseID)
		}
	}
	if *snapshotOnly {
		fmt.Printf("snapshot: %d files, signed=%v, manifest=%s\n",
			len(manifest.Entries), manifest.Signed(), webproxy.ManifestPath(absState))
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
	go func() {
		<-ctx.Done()
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sd)
	}()

	logger.Info("web-layer integrity proxy listening",
		"addr", *listen, "root", absRoot, "files", len(manifest.Entries),
		"signed", manifest.Signed(), "upstream", *upstream)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	logger.Info("proxy stopped")
}

// syncFromControlPlane fetches the signed site manifest, downloads every file and
// verifies it against the signed hashes before writing the local manifest.
func syncFromControlPlane(ctx context.Context, agentStateDir, stateDir string, logger *slog.Logger) (*webproxy.Manifest, error) {
	state, err := config.LoadAgentState(agentStateDir)
	if err != nil {
		return nil, fmt.Errorf("load agent state: %w", err)
	}
	client, err := agent.NewClient(state)
	if err != nil {
		return nil, fmt.Errorf("build control-plane client: %w", err)
	}
	sm, ok, err := client.LatestSiteManifest(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no completed pull-mode release for this node (local-mode releases have no artifacts on the control plane)")
	}
	blobDir := webproxy.BlobDir(stateDir)
	if err := os.MkdirAll(blobDir, 0o750); err != nil {
		return nil, err
	}
	m := &webproxy.Manifest{
		Version:       1,
		CreatedAt:     time.Now().Unix(),
		Entries:       map[string]webproxy.Entry{},
		ReleaseID:     sm.RequestID,
		NodeID:        sm.NodeID,
		TargetDir:     sm.TargetDir,
		ReleaseDigest: sm.Manifest,
		SignedAt:      sm.SignedAt,
		Signature:     sm.Signature,
	}
	for _, f := range sm.Files {
		var buf bytes.Buffer
		n, err := client.DownloadArtifact(ctx, sm.RequestID, f.Path, &buf)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", f.Path, err)
		}
		if n != f.Size {
			return nil, fmt.Errorf("%s: size %d, signed manifest says %d", f.Path, n, f.Size)
		}
		sum := sha256.Sum256(buf.Bytes())
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			return nil, fmt.Errorf("%s: hash %s does not match the signed manifest (%s)", f.Path, got, f.SHA256)
		}
		blob := filepath.Join(blobDir, f.SHA256)
		if _, statErr := os.Stat(blob); statErr != nil {
			if err := os.WriteFile(blob, buf.Bytes(), 0o600); err != nil {
				return nil, err
			}
		}
		m.Entries[f.Path] = webproxy.Entry{SHA256: f.SHA256, Size: f.Size}
	}
	if err := webproxy.SaveManifest(stateDir, m); err != nil {
		return nil, err
	}
	logger.Info("signed artifacts stored", "files", len(m.Entries), "release", sm.RequestID)
	return m, nil
}

// verifyLocalManifest re-verifies the persisted signature against the policy key
// in the agent state, so a tampered manifest on disk is detected at startup.
func verifyLocalManifest(m *webproxy.Manifest, agentStateDir string) error {
	state, err := config.LoadAgentState(agentStateDir)
	if err != nil {
		return err
	}
	pub, err := hex.DecodeString(state.PolicyPub)
	if err != nil || len(pub) != 32 {
		return errors.New("invalid policy public key in agent state")
	}
	sm := &release.SiteManifest{
		NodeID:    m.NodeID,
		RequestID: m.ReleaseID,
		Manifest:  m.ReleaseDigest,
		TargetDir: m.TargetDir,
		SignedAt:  m.SignedAt,
		Signature: m.Signature,
	}
	paths := make([]string, 0, len(m.Entries))
	for p := range m.Entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e := m.Entries[p]
		sm.Files = append(sm.Files, release.SiteFile{Path: p, SHA256: e.SHA256, Size: e.Size})
	}
	return release.VerifySiteManifest(pub, sm)
}
