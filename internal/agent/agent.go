package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/easykeke/tamperguard/internal/attest"
	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/rasp"
	"github.com/easykeke/tamperguard/internal/selfcheck"
	"github.com/easykeke/tamperguard/internal/uninstall"
)

// Options tunes agent behaviour.
type Options struct {
	Logger *slog.Logger
	// AutoUpgrade enables the signed self-upgrade channel.
	AutoUpgrade bool
	// UpgradeInterval controls how often the channel is polled.
	UpgradeInterval time.Duration
	// RASP enables the application-layer probe socket.
	RASP bool
	// RASPSocket overrides the probe socket path (default <stateDir>/rasp.sock).
	RASPSocket string
	// TPMQuoteAK is the path to a TSS2 key context for TPM quote (empty disables).
	TPMQuoteAK string
	// StatusDir, when set, receives status.json for the tray UI.
	StatusDir string
	// TPMQuoteTCTI is the TPM2 TCTI string, e.g. "device:/dev/tpmrm0" or
	// "swtpm:host=127.0.0.1,port=2321".
	TPMQuoteTCTI string
	// Verity enables fs-verity on files installed by pull deliveries.
	Verity bool
}

// Agent is the protect-side runtime: it syncs policy, feeds the enforcer and
// ships a tamper-evident audit chain to the control plane.
type Agent struct {
	state  *config.AgentState
	client *Client
	enf    enforcer.Enforcer
	log    *slog.Logger
	writer *audit.Writer
	file   *os.File
	opts   Options
	rasp   *rasp.Server

	mu           sync.Mutex
	pending      []audit.Record
	policyDigest string
	unhealthy    bool
	reported     []string // grant token IDs last reported to the control plane
	wake         chan struct{}
	upgradeReady chan struct{}
	attestMu     sync.Mutex
	attestNonce  string
}

// New builds an agent from persisted state.
func New(state *config.AgentState, enf enforcer.Enforcer, opts Options) (*Agent, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.AutoUpgrade && opts.UpgradeInterval <= 0 {
		opts.UpgradeInterval = 6 * time.Hour
	}
	priv, err := parsePrivateKey(state.KeyPEM)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(state.StateDir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(state.StateDir, "audit.log")
	writer, f, err := audit.OpenFile(path, state.AgentID, priv)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(state)
	if err != nil {
		f.Close()
		return nil, err
	}
	a := &Agent{state: state, client: client, enf: enf, log: opts.Logger, writer: writer, file: f,
		opts: opts, wake: make(chan struct{}, 1), upgradeReady: make(chan struct{}, 1)}
	if opts.RASP {
		socket := opts.RASPSocket
		if socket == "" {
			socket = filepath.Join(state.StateDir, "rasp.sock")
		}
		srv, err := rasp.New(socket, a.onRASPEvent, opts.Logger)
		if err != nil {
			// The RASP channel is an extra layer: failing to open the socket
			// must not stop the protection agent (e.g. AF_UNIX unavailable).
			a.log.Warn("rasp probe socket unavailable; continuing without runtime probe", "socket", socket, "err", err)
		} else {
			a.rasp = srv
			a.log.Info("rasp probe socket listening", "socket", socket)
		}
	}
	return a, nil
}

func parsePrivateKey(keyPEM string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("agent: private key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("agent: private key is not Ed25519")
	}
	return priv, nil
}

func parsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("agent: public key has %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// Run drives the agent until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	interval := time.Duration(a.state.PollSeconds) * time.Second
	if interval <= 0 {
		interval = 15 * time.Second
	}
	a.log.Info("agent starting", "agent", a.state.AgentID, "role", a.state.Role,
		"enforcer", a.enf.Name(), "degraded", a.enf.Capability().Degraded)

	// Push channel: a policy update, revocation or grant wakes the loop
	// immediately instead of waiting for the next heartbeat. It is an
	// optimisation only -- the heartbeat remains the source of truth.
	go a.streamLoop(ctx)
	go a.selfcheckLoop(ctx)

	// Signed self-upgrade channel. When a new binary is staged the loop stops
	// so the service manager can restart into it.
	if sp, ok := a.enf.(enforcer.SelfProtector); ok {
		paths := a.selfProtectPaths()
		if err := sp.SetSelfPaths(paths); err != nil {
			a.log.Warn("self-protection not applied", "err", err)
		} else {
			a.log.Info("self-protection active", "paths", len(paths))
		}
	}
	if a.opts.AutoUpgrade {
		go a.upgradeLoop(ctx)
	}

	// First sync immediately so a restart applies the current policy fast.
	a.tick(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.shutdown()
			return nil
		case <-t.C:
			a.tick(ctx)
		case <-a.wake:
			a.tick(ctx)
		case <-a.upgradeReady:
			a.shutdown()
			return ErrUpgradeStaged
		}
	}
}

// upgradeLoop polls the signed upgrade channel.
func (a *Agent) upgradeLoop(ctx context.Context) {
	interval := a.opts.UpgradeInterval
	if interval <= 0 {
		return
	}
	check := func() {
		staged, err := MaybeUpgrade(ctx, a.state, a.client, a.log, Version)
		if err != nil {
			a.log.Warn("upgrade check failed", "err", err)
			return
		}
		if staged {
			select {
			case a.upgradeReady <- struct{}{}:
			default:
			}
		}
	}
	check()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// streamLoop keeps the push connection alive with exponential backoff.
func (a *Agent) streamLoop(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := a.client.Stream(ctx, func(kind string, data []byte) {
			if kind == "uninstall" {
				a.handleRemoteUninstall(data)
				return
			}
			select {
			case a.wake <- struct{}{}:
			default:
			}
		})
		if ctx.Err() != nil {
			return
		}
		a.log.Warn("push stream disconnected", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// handleRemoteUninstall reacts to a ticket pushed by the management plane. The
// ticket is verified against the control-plane policy key before anything is
// removed; cleanup runs detached because stopping the service terminates this
// process.
func (a *Agent) handleRemoteUninstall(data []byte) {
	var ev struct {
		Payload struct {
			Ticket string `json:"ticket"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(data, &ev); err != nil || ev.Payload.Ticket == "" {
		return
	}
	tk, err := a.client.VerifyUninstallTicket(ev.Payload.Ticket, a.state.AgentID, "")
	if err != nil {
		a.log.Error("remote uninstall ticket rejected", "err", err)
		return
	}
	a.log.Warn("control plane approved uninstall; removing agent", "request", tk.RequestID)
	exe, _ := os.Executable()
	unit, service := uninstall.DefaultSystemTargets()
	opts := uninstall.Options{
		StateDir:    a.state.StateDir,
		BinaryPath:  exe,
		UnitPath:    unit,
		ServiceName: service,
	}
	if err := uninstall.SpawnDetached(opts); err != nil {
		a.log.Error("cannot schedule uninstall cleanup", "err", err)
		return
	}
	// Give the audit queue a moment to flush; the detached helper takes over.
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}

// selfcheckLoop keeps a baseline of the agent's own files and periodically
// verifies it. A mismatch is appended to the signed audit chain; it is detection,
// not prevention (a root user can still replace the binary).
func (a *Agent) selfcheckLoop(ctx context.Context) {
	baseline := filepath.Join(a.state.StateDir, "selfcheck.json")
	paths := a.selfcheckPaths()
	if _, err := os.Stat(baseline); err != nil {
		m, err := selfcheck.Build(paths)
		if err != nil {
			a.log.Warn("self-check baseline not created", "err", err)
		} else if err := selfcheck.Save(baseline, m); err != nil {
			a.log.Warn("self-check baseline not saved", "err", err)
		} else {
			a.log.Info("self-check baseline created", "files", len(m.Files))
		}
	} else {
		a.runSelfcheck(baseline)
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.runSelfcheck(baseline)
		}
	}
}

// selfProtectPaths are the agent files protected in the kernel. The executable is
// deliberately excluded: protecting its inode makes every later exec of that
// binary fail (the loader's mmap/mprotect calls hit the same hooks), which would
// break upgrades and even `tg-agent ebpf-detach`. The binary is covered by the
// self-check baseline and by root-owned 0755 permissions instead.
func (a *Agent) selfProtectPaths() []string {
	paths := []string{filepath.Join(a.state.StateDir, config.AgentStateFile)}
	if runtime.GOOS == "linux" {
		unit := "/etc/systemd/system/tamperguard-agent.service"
		if _, err := os.Stat(unit); err == nil {
			paths = append(paths, unit)
		}
	}
	return paths
}

func (a *Agent) selfcheckPaths() []string {
	paths := []string{filepath.Join(a.state.StateDir, config.AgentStateFile)}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, exe)
	}
	if runtime.GOOS == "linux" {
		unit := "/etc/systemd/system/tamperguard-agent.service"
		if _, err := os.Stat(unit); err == nil {
			paths = append(paths, unit)
		}
	}
	return paths
}

func (a *Agent) runSelfcheck(baseline string) {
	m, err := selfcheck.Load(baseline)
	if err != nil {
		a.log.Warn("self-check baseline unreadable", "err", err)
		return
	}
	diffs, err := selfcheck.Compare(m)
	if err != nil {
		a.log.Warn("self-check failed", "err", err)
		return
	}
	for _, d := range diffs {
		a.log.Error("agent file changed since the baseline", "diff", d.String())
		a.record(audit.KindAgentSelfcheck, d.Path, d.String())
	}
}

func (a *Agent) tick(ctx context.Context) {
	a.drainEvents()
	if err := a.sync(ctx); err != nil {
		a.log.Warn("heartbeat failed", "err", err)
	}
	a.maybeAttest(ctx)
	if a.state.Role == "protect" {
		a.deliverPending(ctx)
	}
	if err := a.flush(ctx); err != nil {
		a.log.Warn("audit upload failed", "err", err)
	}
	a.writeTrayStatus()
}

func (a *Agent) sync(ctx context.Context) error {
	capb := a.enf.Capability()
	if ev := attest.Collect(""); !ev.Empty() {
		capb.BootDigest = ev.Digest
		capb.SecureBoot = ev.SecureBoot
		capb.TPM = ev.TPM
		capb.IMA = ev.IMA
	}
	capsJSON, _ := json.Marshal(capb)
	healthErr := a.enf.Health()

	a.mu.Lock()
	digest := a.policyDigest
	a.mu.Unlock()

	resp, err := a.client.Heartbeat(ctx, HeartbeatRequest{
		Status:          "online",
		Enforcer:        a.enf.Name(),
		PolicyDigest:    digest,
		Caps:            capsJSON,
		Degraded:        capb.Degraded,
		AgentVersion:    Version,
		EnforcerHealthy: healthErr == nil,
		AuditSeq:        a.writer.NextSeq() - 1,
	})
	if err != nil {
		return err
	}
	if resp.AttestNonce != "" {
		a.attestMu.Lock()
		a.attestNonce = resp.AttestNonce
		a.attestMu.Unlock()
	}

	revs := enforcer.RevocationSet{}
	for _, r := range resp.Revocations {
		revs[r.Kind+":"+r.Value] = true
	}

	var snap *policy.Snapshot
	if resp.Policy != nil {
		pub, err := parsePublicKeyHex(a.state.PolicyPub)
		if err != nil {
			a.record(audit.KindEnforcerError, "", "policy key unusable: "+err.Error())
			return nil
		}
		if err := resp.Policy.Verify(pub); err != nil {
			// A policy we cannot authenticate is never applied.
			a.record(audit.KindEnforcerError, "", "policy snapshot rejected: "+err.Error())
			return nil
		}
		snap = resp.Policy
	}

	// Translate the policy's allowed writers into kernel uids BEFORE applying
	// the runtime: the grant map is built from the uid set, so configuring uids
	// afterwards would leave the current token without grant entries.
	if cfg, ok := a.enf.(enforcer.UIDConfigurer); ok {
		uids := effectivePublisherUIDs(a.state.PublisherUIDs, snap)
		if err := cfg.SetPublisherUIDs(uids); err != nil {
			a.log.Warn("update publisher uids failed", "err", err)
		}
	}
	rt := enforcer.Runtime{
		Policy:      snap,
		Grants:      resp.Grants,
		Revocations: revs,
		UpdatedAt:   resp.ServerTime,
	}
	if err := a.enf.Update(rt); err != nil {
		a.record(audit.KindEnforcerError, "", "enforcer update failed: "+err.Error())
		return nil
	}
	a.pushRASPRules(snap)

	newDigest := ""
	if snap != nil {
		newDigest = snap.Digest
	}
	a.mu.Lock()
	changed := newDigest != a.policyDigest
	a.policyDigest = newDigest
	a.mu.Unlock()
	if changed {
		a.record(audit.KindPolicyApplied, "", "policy digest "+newDigest)
	}

	// Tell the control plane which tokens are actually installed, so a
	// publisher can wait for this acknowledgement instead of guessing.
	active := make([]string, 0, len(resp.Grants))
	for _, g := range resp.Grants {
		if g.TokenID != "" {
			active = append(active, g.TokenID)
		}
	}
	a.mu.Lock()
	prev := a.reported
	a.reported = active
	a.mu.Unlock()
	if !sameStrings(prev, active) {
		if err := a.client.ReportGrants(ctx, active); err != nil {
			a.log.Warn("grant report failed", "err", err)
		}
	}
	return nil
}

// effectivePublisherUIDs merges the configured publisher uids with the uids
// declared by process writer rules in the policy. Duplicates are removed and
// order is stable so repeated syncs are idempotent.
func effectivePublisherUIDs(base []int, snap *policy.Snapshot) []int {
	seen := make(map[int]bool, len(base)+4)
	out := make([]int, 0, len(base)+4)
	add := func(uid int) {
		if seen[uid] {
			return
		}
		seen[uid] = true
		out = append(out, uid)
	}
	for _, u := range base {
		add(u)
	}
	if snap != nil {
		for _, w := range snap.Policy.Writers {
			if w.Kind == policy.WriterProcess && w.UID != nil {
				add(*w.UID)
			}
		}
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// drainEvents moves enforcer events into the audit queue.
func (a *Agent) drainEvents() {
	for {
		select {
		case ev, ok := <-a.enf.Events():
			if !ok {
				return
			}
			a.recordEvent(ev)
		default:
			return
		}
	}
}

func (a *Agent) recordEvent(ev enforcer.Event) {
	subject := fmt.Sprintf("pid:%d uid:%d exe:%s", ev.Subject.PID, ev.Subject.UID, ev.Subject.ExePath)
	detail := ev.Reason
	if ev.Rule != "" {
		detail = "rule=" + ev.Rule + " reason=" + ev.Reason
	}
	r, err := a.writer.Append(audit.Record{
		Time:     ev.Time,
		Kind:     ev.Kind,
		Path:     ev.Path,
		Op:       string(ev.Op),
		Subject:  subject,
		TokenID:  ev.TokenID,
		Detail:   detail,
		Decision: decisionWord(ev.Kind),
	})
	if err != nil {
		a.log.Error("audit append failed", "err", err)
		return
	}
	a.enqueue(r)
}

func decisionWord(kind string) string {
	switch kind {
	case audit.KindWriteBlocked:
		return "deny"
	case audit.KindWriteObserved:
		return "observe"
	default:
		return "allow"
	}
}

func (a *Agent) record(kind, path, detail string) {
	r, err := a.writer.Append(audit.Record{Kind: kind, Path: path, Detail: detail})
	if err != nil {
		a.log.Error("audit append failed", "err", err)
		return
	}
	a.enqueue(r)
}

const maxPending = 5000

func (a *Agent) enqueue(r audit.Record) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.pending) >= maxPending {
		// Dropping the oldest is better than unbounded memory growth, but the
		// sequence gap it creates will be detected by the server, which is the
		// intended behaviour: a silent drop is not acceptable.
		a.pending = a.pending[1:]
	}
	a.pending = append(a.pending, r)
}

func (a *Agent) flush(ctx context.Context) error {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return nil
	}
	n := len(a.pending)
	if n > 200 {
		n = 200
	}
	batch := make([]audit.Record, n)
	copy(batch, a.pending[:n])
	a.mu.Unlock()

	if _, err := a.client.UploadAudit(ctx, batch); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 409 {
			a.log.Error("control plane rejected audit chain", "detail", apiErr.Body)
			a.mu.Lock()
			a.unhealthy = true
			a.mu.Unlock()
		}
		return err
	}
	a.mu.Lock()
	a.pending = a.pending[n:]
	a.mu.Unlock()

	if f := a.file; f != nil {
		_ = f.Sync()
	}
	return nil
}

// pushRASPRules delivers the current protection rules to connected probes.
func (a *Agent) pushRASPRules(snap *policy.Snapshot) {
	if a.rasp == nil {
		return
	}
	rules := []rasp.Rule{}
	if snap != nil {
		for _, p := range snap.Policy.Paths {
			rules = append(rules, rasp.Rule{Path: p.Path, Recursive: p.Recursive, Mode: string(p.Mode)})
		}
	}
	a.rasp.UpdateRules(rules)
}

// onRASPEvent records one probe decision in the audit chain.
func (a *Agent) onRASPEvent(ev rasp.Event) {
	kind := audit.KindRASPObserved
	decision := "observe"
	if ev.Decision == "blocked" {
		kind = audit.KindRASPBlocked
		decision = "deny"
	}
	detail := ev.Stack
	if len(detail) > 512 {
		detail = detail[:512]
	}
	r, err := a.writer.Append(audit.Record{
		Kind:     kind,
		Path:     ev.Path,
		Op:       ev.Op,
		Subject:  fmt.Sprintf("rasp pid:%d app:%s", ev.PID, ev.App),
		Decision: decision,
		Detail:   detail,
	})
	if err != nil {
		a.log.Error("rasp audit append failed", "err", err)
		return
	}
	a.enqueue(r)
}

func (a *Agent) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.flush(ctx)
	if a.rasp != nil {
		_ = a.rasp.Close()
	}
	_ = a.enf.Close()
	if a.file != nil {
		_ = a.file.Sync()
		_ = a.file.Close()
	}
	a.log.Info("agent stopped")
}
