// Package publish implements the release agent: it hashes the source tree,
// asks the control plane for a short-lived token bound to that manifest, and
// writes the files only after re-checking every individual hash.
//
// The browser never touches the token; the token never touches disk.
package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/fsverity"
	"github.com/easykeke/tamperguard/internal/store"
	"github.com/easykeke/tamperguard/internal/token"
)

// Entry is one file in the release manifest.
type Entry struct {
	Rel    string // slash-separated path relative to the source root
	SHA256 string
	Size   int64
}

// Manifest is a deterministic description of a release tree.
type Manifest struct {
	Digest  string
	Entries []Entry
}

// BuildManifest walks root and hashes every regular file.
// Symlinks are rejected rather than followed: following them would let a
// compromised release tree publish files from outside the trusted directory.
func BuildManifest(root string) (*Manifest, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("publish: refusing to follow symlink %s", path)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("publish: unsupported file type at %s", path)
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, Entry{Rel: filepath.ToSlash(rel), SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("publish: source tree contains no regular files")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Rel < entries[j].Rel })
	return &Manifest{Digest: digestOf(entries), Entries: entries}, nil
}

func digestOf(entries []Entry) string {
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\t%s\n", e.Rel, e.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Agent derives the file entries for the control plane request.
func (m *Manifest) Agent() []agent.FileEntry {
	out := make([]agent.FileEntry, 0, len(m.Entries))
	for _, e := range m.Entries {
		out = append(out, agent.FileEntry{Path: e.Rel, SHA256: e.SHA256, Size: e.Size})
	}
	return out
}

// Publisher runs the release side.
type Publisher struct {
	state     *config.AgentState
	client    *agent.Client
	issuerPub ed25519.PublicKey
	log       *slog.Logger
	interval  time.Duration
	verity    bool
}

// New builds a publisher from persisted state. verity enables fs-verity on the
// files of every release it installs locally.
func New(state *config.AgentState, logger *slog.Logger, verity bool) (*Publisher, error) {
	if logger == nil {
		logger = slog.Default()
	}
	pub, err := hexKey(state.IssuerPub)
	if err != nil {
		return nil, err
	}
	client, err := agent.NewClient(state)
	if err != nil {
		return nil, err
	}
	interval := time.Duration(state.PollSeconds) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Publisher{state: state, client: client, issuerPub: pub, log: logger, interval: interval}, nil
}

func hexKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("publish: issuer key has %d bytes", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// Run polls for release requests until ctx is cancelled.
func (p *Publisher) Run(ctx context.Context) error {
	p.log.Info("publish agent starting", "agent", p.state.AgentID, "poll", p.interval)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			p.log.Info("publish agent stopped")
			return nil
		case <-t.C:
			p.poll(ctx)
		}
	}
}

func (p *Publisher) poll(ctx context.Context) {
	reqs, err := p.client.PendingRequests(ctx)
	if err != nil {
		p.log.Warn("list pending requests failed", "err", err)
		return
	}
	for _, req := range reqs {
		if req.Status != store.PublishPending {
			// Requests already holding a token are not retried: a token is
			// single-shot by design, and a half-finished release must be
			// re-created rather than silently resumed with stale content.
			continue
		}
		if err := p.handle(ctx, req); err != nil {
			p.log.Error("publish failed", "request", req.ID, "err", err)
			_ = p.client.CompleteRequest(ctx, req.ID, false, err.Error())
		}
	}
}

func (p *Publisher) handle(ctx context.Context, req store.PublishRequest) error {
	if req.SourceDir == "" || req.TargetDir == "" {
		return errors.New("publish: request is missing source_dir or target_dir")
	}
	man, err := BuildManifest(req.SourceDir)
	if err != nil {
		return err
	}
	p.log.Info("manifest built", "request", req.ID, "files", len(man.Entries), "digest", man.Digest)

	if req.Delivery == store.DeliveryPull {
		return p.publishPull(ctx, req, man)
	}

	grant, err := p.client.SubmitManifest(ctx, req.ID, man.Digest, man.Agent())
	if err != nil {
		return fmt.Errorf("publish: submit manifest: %w", err)
	}
	claims, err := token.Verify(p.issuerPub, grant.Token, time.Now())
	if err != nil {
		return fmt.Errorf("publish: token rejected: %w", err)
	}
	if claims.Subject != p.state.AgentID {
		return fmt.Errorf("publish: token subject %q is not this agent", claims.Subject)
	}
	if claims.NodeID != req.NodeID {
		return fmt.Errorf("publish: token targets node %q, request targets %q", claims.NodeID, req.NodeID)
	}
	if err := claims.CheckManifest(man.Digest); err != nil {
		return err
	}

	// The token is signed, but the target node only learns the matching grant
	// when it syncs. Ask the control plane whether the node has confirmed the
	// grant before writing; the retry loop still tolerates a late arrival.
	if err := p.waitGrantReady(ctx, req.ID, 10*time.Second); err != nil {
		p.log.Warn("grant not confirmed by the node in time; attempting the write anyway",
			"request", req.ID, "err", err)
	}

	written, err := p.writeWithGrantSettle(req, man, claims)
	if err != nil {
		return err
	}
	p.log.Info("release written", "request", req.ID, "files", written, "token", claims.TokenID)
	if p.verity {
		p.enableVerity(req, man)
	}
	if err := p.client.CompleteRequest(ctx, req.ID, true, ""); err != nil {
		return fmt.Errorf("publish: report completion: %w", err)
	}
	return nil
}

// publishPull stages every file on the control plane and stops. The target
// node's agent fetches, verifies and writes them, so the publisher never needs
// network access to the protected host.
func (p *Publisher) publishPull(ctx context.Context, req store.PublishRequest, man *Manifest) error {
	for _, e := range man.Entries {
		src := filepath.Join(req.SourceDir, filepath.FromSlash(e.Rel))
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(e.SHA256)) != 1 {
			return fmt.Errorf("publish: %s changed after hashing", src)
		}
		if err := p.client.UploadArtifact(ctx, req.ID, e.Rel, got, data); err != nil {
			return fmt.Errorf("publish: upload %s: %w", e.Rel, err)
		}
	}
	if _, err := p.client.SubmitManifest(ctx, req.ID, man.Digest, man.Agent()); err != nil {
		return fmt.Errorf("publish: submit manifest: %w", err)
	}
	p.log.Info("release staged for pull delivery", "request", req.ID, "files", len(man.Entries))
	return nil
}

// enableVerity hardens the files just written: fs-verity makes them read-only
// and verifies every read against a Merkle tree, so even out-of-band tampering
// surfaces as EIO instead of attacker content. Best effort: on a filesystem
// without verity support a single warning is logged (the kernel enforcer still
// protects the tree).
func (p *Publisher) enableVerity(req store.PublishRequest, man *Manifest) {
	for _, e := range man.Entries {
		dst := filepath.Join(req.TargetDir, filepath.FromSlash(e.Rel))
		if err := fsverity.Enable(dst); err != nil {
			p.log.Warn("fs-verity not applied; release remains protected by the kernel enforcer",
				"request", req.ID, "file", dst, "err", err)
			return
		}
	}
	p.log.Info("release hardened with fs-verity", "request", req.ID, "files", len(man.Entries))
}

// writeWithGrantSettle retries while the protected node has not yet installed
// the grant.
//
// The token is issued to the publisher, but the kernel only learns about it
// when the protect agent's next heartbeat delivers the grant. That window is
// normally well under one heartbeat interval, so retrying on EPERM is enough.
// A push channel (SSE) or an explicit grant-ready acknowledgement replaces this
// polling in P1; until then, publishing to a node whose heartbeat is 15 s away
// needs to tolerate a few seconds of denials.
func (p *Publisher) writeWithGrantSettle(req store.PublishRequest, man *Manifest, claims *token.Claims) (int, error) {
	deadline := time.Unix(claims.ExpiresAt, 0).Add(-10 * time.Second)
	for attempt := 1; ; attempt++ {
		written, err := p.writeTree(req, man, claims)
		if err == nil {
			if attempt > 1 {
				p.log.Info("release written after grant propagation", "attempts", attempt)
			}
			return written, nil
		}
		if !isPermissionErr(err) || time.Now().After(deadline) || attempt >= 15 {
			return written, err
		}
		p.log.Warn("write denied, waiting for the grant to reach the node", "attempt", attempt, "err", err)
		time.Sleep(2 * time.Second)
	}
}

// waitGrantReady polls the control plane until the target node reports the
// grant as installed.
func (p *Publisher) waitGrantReady(ctx context.Context, requestID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ready, err := p.client.PublishReady(ctx, requestID)
		if err == nil && ready {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return errors.New("publish: grant not confirmed before timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func isPermissionErr(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// writeTree verifies every file against both the manifest and the token before
// replacing anything on disk.
func (p *Publisher) writeTree(req store.PublishRequest, man *Manifest, claims *token.Claims) (int, error) {
	root, err := filepath.Abs(req.TargetDir)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, e := range man.Entries {
		src := filepath.Join(req.SourceDir, filepath.FromSlash(e.Rel))
		dst := filepath.Join(root, filepath.FromSlash(e.Rel))
		// Defence in depth: the manifest was built from the source walk, but a
		// client-side bug must never be able to escape the target directory.
		if rel, err := filepath.Rel(root, dst); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return written, fmt.Errorf("publish: %s escapes target directory", e.Rel)
		}
		if !claims.Covers(dst) {
			return written, fmt.Errorf("publish: token does not authorise %s", dst)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return written, err
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(e.SHA256)) != 1 {
			return written, fmt.Errorf("publish: %s changed after hashing (manifest says %s, file is %s)", src, e.SHA256, got)
		}
		if err := writeAtomic(dst, data); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func writeAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tg-release-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, dst)
}
