package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/release"
	"github.com/easykeke/tamperguard/internal/store"
	"github.com/easykeke/tamperguard/internal/tpmquote"
	"github.com/easykeke/tamperguard/internal/uninstall"
)

// Client talks to the control plane over mutual TLS.
type Client struct {
	base      string
	hc        *http.Client
	policyPub ed25519.PublicKey
}

// NewClient builds a client from persisted agent state.
func NewClient(state *config.AgentState) (*Client, error) {
	cert, err := tls.X509KeyPair([]byte(state.CertPEM), []byte(state.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("agent: load client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(state.CACertPEM)) {
		return nil, errors.New("agent: CA certificate is not valid PEM")
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	tr := &http.Transport{
		TLSClientConfig:     conf,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	policyPub, err := decodeHexKey(state.PolicyPub)
	if err != nil {
		return nil, fmt.Errorf("agent: policy public key: %w", err)
	}
	return &Client{
		base:      strings.TrimRight(state.ServerURL, "/"),
		hc:        &http.Client{Transport: tr, Timeout: 30 * time.Second},
		policyPub: policyPub,
	}, nil
}

// doJSON performs one JSON round trip.
func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("agent: decode response: %w", err)
		}
	}
	return nil
}

// APIError is a non-2xx response from the control plane.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane returned %d: %s", e.Status, strings.TrimSpace(e.Body))
}

// ---------- heartbeat ----------

// HeartbeatRequest is what the agent reports every interval.
type HeartbeatRequest struct {
	Status          string          `json:"status"`
	Enforcer        string          `json:"enforcer"`
	PolicyDigest    string          `json:"policy_digest"`
	Caps            json.RawMessage `json:"caps"`
	Degraded        bool            `json:"degraded"`
	AgentVersion    string          `json:"agent_version"`
	EnforcerHealthy bool            `json:"enforcer_healthy"`
	AuditSeq        uint64          `json:"audit_seq"`
}

// RevocationEntry is one item of the pushed revocation list.
type RevocationEntry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// HeartbeatResponse carries policy, grants and revocations.
type HeartbeatResponse struct {
	AttestNonce       string            `json:"attest_nonce,omitempty"`
	Policy            *policy.Snapshot  `json:"policy"`
	Grants            []policy.Grant    `json:"grants"`
	Revocations       []RevocationEntry `json:"revocations"`
	ServerTime        int64             `json:"server_time"`
	HeartbeatInterval int               `json:"heartbeat_interval"`
}

// Heartbeat sends one liveness + sync request.
func (c *Client) Heartbeat(ctx context.Context, in HeartbeatRequest) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/heartbeat", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UploadAttestation submits a TPM quote for server-side verification.
func (c *Client) UploadAttestation(ctx context.Context, nonce string, ev tpmquote.Evidence) error {
	req := map[string]any{
		"nonce":     nonce,
		"attest":    base64.StdEncoding.EncodeToString(ev.Attest),
		"signature": base64.StdEncoding.EncodeToString(ev.Signature),
		"pcr":       base64.StdEncoding.EncodeToString(ev.PCR),
		"indexes":   ev.Indexes,
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agent/attest", req, nil)
}

// ---------- audit ----------

// UploadAudit sends a batch of sealed records.
func (c *Client) UploadAudit(ctx context.Context, records []audit.Record) (uint64, error) {
	var out struct {
		AckSeq uint64 `json:"ack_seq"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/audit",
		map[string]any{"records": records}, &out); err != nil {
		return 0, err
	}
	return out.AckSeq, nil
}

// ReportGrants tells the control plane which release tokens are installed.
func (c *Client) ReportGrants(ctx context.Context, tokens []string) error {
	if tokens == nil {
		tokens = []string{}
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agent/grants",
		map[string]any{"active_tokens": tokens}, nil)
}

// Stream consumes the server-sent event channel until ctx is cancelled or the
// connection drops. handler is called for each event and must not block.
func (c *Client) Stream(ctx context.Context, handler func(kind string, data []byte)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/agent/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	// A stream must not inherit the request timeout of the regular client.
	streamClient := &http.Client{Transport: c.hc.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}

	reader := bufio.NewReader(resp.Body)
	var event string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue // comment / keep-alive
		}
		field, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch field {
		case "event":
			event = value
		case "data":
			handler(event, []byte(value))
		}
	}
}

// ---------- publisher endpoints ----------

// PendingRequests lists release requests assigned to this publisher.
func (c *Client) PendingRequests(ctx context.Context) ([]store.PublishRequest, error) {
	var out []store.PublishRequest
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/pending", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FileEntry is one file in a release manifest.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// TokenGrant is the control plane's answer to a manifest submission.
type TokenGrant struct {
	Token     string   `json:"token"`
	TokenID   string   `json:"token_id"`
	ExpiresAt int64    `json:"expires_at"`
	Paths     []string `json:"paths"`
}

// SubmitManifest reports the release manifest and receives a release token.
func (c *Client) SubmitManifest(ctx context.Context, id, manifest string, files []FileEntry) (*TokenGrant, error) {
	var out TokenGrant
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/publish/"+id+"/manifest",
		map[string]any{"manifest": manifest, "files": files}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompleteRequest closes a publish request.
func (c *Client) CompleteRequest(ctx context.Context, id string, ok bool, errMsg string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/publish/"+id+"/complete",
		map[string]any{"ok": ok, "error": errMsg}, nil)
}

// PublishReady reports whether the target node has installed the grant for
// this request's token.
func (c *Client) PublishReady(ctx context.Context, id string) (bool, error) {
	var out struct {
		Ready bool `json:"ready"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/"+id+"/ready", nil, &out); err != nil {
		return false, err
	}
	return out.Ready, nil
}

// decodeHexKey parses a hex-encoded Ed25519 public key from the agent state.
func decodeHexKey(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// LatestSiteManifest fetches and verifies the control-plane-signed description of
// the site this node should be serving. ok=false means no completed pull release
// exists yet.
func (c *Client) LatestSiteManifest(ctx context.Context) (sm *release.SiteManifest, ok bool, err error) {
	var got release.SiteManifest
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/manifest", nil, &got); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	if err := release.VerifySiteManifest(c.policyPub, &got); err != nil {
		return nil, false, err
	}
	return &got, true, nil
}

// ---------- uninstall ----------

// UninstallStatus is the control-plane answer for a pending request.
type UninstallStatus struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Ticket    string `json:"ticket"`
}

// RequestUninstall creates a client-initiated uninstall request. The returned id
// is polled until an administrator approves or denies it.
func (c *Client) RequestUninstall(ctx context.Context, nonce, reason string) (string, error) {
	var out struct {
		RequestID string `json:"request_id"`
		Status    string `json:"status"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agent/uninstall/request",
		map[string]string{"nonce": nonce, "reason": reason}, &out); err != nil {
		return "", err
	}
	return out.RequestID, nil
}

// GetUninstallStatus polls a request.
func (c *Client) GetUninstallStatus(ctx context.Context, id string) (*UninstallStatus, error) {
	var out UninstallStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/uninstall/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyUninstallTicket checks the control-plane signature, the target node and
// (when nonce is not empty) the request nonce.
func (c *Client) VerifyUninstallTicket(encoded, nodeID, nonce string) (*uninstall.Ticket, error) {
	tk, err := uninstall.DecodeTicket(encoded)
	if err != nil {
		return nil, fmt.Errorf("agent: decode uninstall ticket: %w", err)
	}
	if err := uninstall.Verify(c.policyPub, tk, time.Now()); err != nil {
		return nil, err
	}
	if tk.NodeID != nodeID {
		return nil, fmt.Errorf("agent: uninstall ticket targets node %q", tk.NodeID)
	}
	if nonce != "" && tk.Nonce != nonce {
		return nil, errors.New("agent: uninstall ticket nonce does not match this request")
	}
	return tk, nil
}

// ---------- pull delivery ----------

// DeliveryInfo describes one pull-mode release waiting for this node.
type DeliveryInfo struct {
	Request   store.PublishRequest `json:"request"`
	Files     []store.PublishFile  `json:"files"`
	Manifest  string               `json:"manifest"`
	TargetDir string               `json:"target_dir"`
}

// PendingDeliveries lists pull releases waiting for this node.
func (c *Client) PendingDeliveries(ctx context.Context) ([]store.PublishRequest, error) {
	var out []store.PublishRequest
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/deliveries", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeliveryInfo returns the manifest and file list of one delivery.
func (c *Client) DeliveryInfo(ctx context.Context, id string) (*DeliveryInfo, error) {
	var out DeliveryInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/deliveries/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DownloadArtifact streams one file of a delivery into w.
func (c *Client) DownloadArtifact(ctx context.Context, id, relPath string, w io.Writer) (int64, error) {
	q := url.Values{}
	q.Set("path", relPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/v1/agent/deliveries/"+id+"/artifact?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return 0, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	return io.Copy(w, resp.Body)
}

// CompleteDelivery reports the outcome of a pull delivery.
func (c *Client) CompleteDelivery(ctx context.Context, id string, ok bool, errMsg string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agent/deliveries/"+id+"/complete",
		map[string]any{"ok": ok, "error": errMsg}, nil)
}

// UploadArtifact stages one file of a pull-mode release on the control plane.
func (c *Client) UploadArtifact(ctx context.Context, requestID, relPath, sha256Hex string, data []byte) error {
	q := url.Values{}
	q.Set("path", relPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/publish/"+requestID+"/artifact?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-TG-SHA256", sha256Hex)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	return nil
}

// ProtectNode is one target listed for the publisher's setup wizard.
type ProtectNode struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"`
}

// ProtectNodes lists live protect nodes (publisher role).
func (c *Client) ProtectNodes(ctx context.Context) ([]ProtectNode, error) {
	var out []ProtectNode
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/nodes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SyncProfile is a console-managed sync target owned by one publisher.
type SyncProfile struct {
	ID          string `json:"id"`
	PublisherID string `json:"publisher_id"`
	NodeID      string `json:"node_id"`
	SourceDir   string `json:"source_dir"`
	TargetDir   string `json:"target_dir"`
	Mode        string `json:"mode"`
	Delivery    string `json:"delivery"`
	Enabled     bool   `json:"enabled"`
	LastRunAt   int64  `json:"last_run_at"`
	LastStatus  string `json:"last_status"`
}

// SyncProfiles lists the enabled profiles assigned to this publisher.
func (c *Client) SyncProfiles(ctx context.Context) ([]SyncProfile, error) {
	var out []SyncProfile
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/profiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PublishSyncProfile triggers a console-configured profile. Paths and mode come
// from the control plane; only the source directory may be overridden locally.
func (c *Client) PublishSyncProfile(ctx context.Context, profileID, source, node, target, mode, delivery, note string) (*store.PublishRequest, error) {
	body := map[string]string{"profile_id": profileID, "note": note}
	for k, v := range map[string]string{
		"source_dir": source, "node_id": node, "target_dir": target,
		"mode": mode, "delivery": delivery,
	} {
		if v != "" {
			body[k] = v
		}
	}
	var out store.PublishRequest
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/publish/sync", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PublishSync creates a release request from the publisher itself (manual
// trigger), instead of an administrator creating one in the console.
func (c *Client) PublishSync(ctx context.Context, nodeID, sourceDir, targetDir, note, mode, delivery string) (*store.PublishRequest, error) {
	var out store.PublishRequest
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/publish/sync", map[string]string{
		"node_id":    nodeID,
		"source_dir": sourceDir,
		"target_dir": targetDir,
		"note":       note,
		"mode":       mode,
		"delivery":   delivery,
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CurrentRelease returns the files of the last completed release for a node, so
// an incremental publisher can skip unchanged files without target access.
func (c *Client) CurrentRelease(ctx context.Context, nodeID string) (mode, targetDir string, files []FileEntry, err error) {
	q := url.Values{}
	q.Set("node_id", nodeID)
	var out struct {
		Mode      string      `json:"mode"`
		TargetDir string      `json:"target_dir"`
		Files     []FileEntry `json:"files"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/current?"+q.Encode(), nil, &out); err != nil {
		return "", "", nil, err
	}
	return out.Mode, out.TargetDir, out.Files, nil
}

// GetPublishRequest returns one request to its publisher.
func (c *Client) GetPublishRequest(ctx context.Context, id string) (*store.PublishRequest, error) {
	var out store.PublishRequest
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/publish/"+id, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------- self upgrade ----------

// UpgradeInfo is the control plane's answer to an upgrade check.
type UpgradeInfo struct {
	Available bool             `json:"available"`
	Current   string           `json:"current"`
	Manifest  release.Manifest `json:"manifest"`
}

// UpgradeInfo asks whether a newer signed build exists for this platform.
func (c *Client) UpgradeInfo(ctx context.Context, current, osName, arch string) (*UpgradeInfo, error) {
	q := url.Values{}
	q.Set("current", current)
	q.Set("os", osName)
	q.Set("arch", arch)
	var out UpgradeInfo
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agent/upgrade?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DownloadUpgrade streams the artefact into w and returns the byte count.
func (c *Client) DownloadUpgrade(ctx context.Context, m release.Manifest, w io.Writer) (int64, error) {
	q := url.Values{}
	q.Set("version", m.Version)
	q.Set("os", m.OS)
	q.Set("arch", m.Arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/api/v1/agent/upgrade/download?"+q.Encode(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return 0, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	return io.Copy(w, resp.Body)
}

// ---------- enrolment ----------

// EnrollOptions configures first-time enrolment.
type EnrollOptions struct {
	// TPMAKPub is the PEM-encoded TPM attestation key public key, if the host
	// should be able to submit TPM quotes.
	TPMAKPub       string
	TPMAKCtx       string
	TPMTCTI        string
	ServerURL      string
	BootstrapToken string
	Role           string
	StateDir       string
	CAFile         string // PEM path, preferred
	CAFingerprint  string // sha256 of the server certificate DER, hex
	Hostname       string
	PublishDir     string
	PollSeconds    int
	PublisherUIDs  []int
	PublisherSIDs  []string
}

type enrollResponse struct {
	AgentID     string            `json:"agent_id"`
	CertPEM     string            `json:"cert_pem"`
	CAPEM       string            `json:"ca_pem"`
	ServerTime  int64             `json:"server_time"`
	AgentConfig map[string]string `json:"config"`
}

// Enroll performs first-time registration: generate a key, submit a CSR, and
// persist the resulting identity. The bootstrap token is single use.
func Enroll(ctx context.Context, opts EnrollOptions) (*config.AgentState, error) {
	if opts.ServerURL == "" {
		return nil, errors.New("agent: server URL is required")
	}
	if opts.BootstrapToken == "" {
		return nil, errors.New("agent: bootstrap token is required")
	}
	if opts.Role == "" {
		opts.Role = "protect"
	}
	if opts.Role != "protect" && opts.Role != "publish" {
		return nil, errors.New("agent: role must be protect or publish")
	}
	if opts.StateDir == "" {
		opts.StateDir = config.DefaultDataDir
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: opts.Hostname}},
		priv)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// TLS: the server certificate is self-signed by the product CA, so either
	// the CA file or its fingerprint must be supplied. We never fall back to
	// "trust anything".
	var rootCAs *x509.CertPool
	var verify func([][]byte, [][]*x509.Certificate) error
	if opts.CAFile != "" {
		pemBytes, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("agent: read CA file: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("agent: CA file contains no certificate")
		}
	} else if opts.CAFingerprint != "" {
		want := strings.ToLower(strings.ReplaceAll(opts.CAFingerprint, ":", ""))
		verify = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("agent: server presented no certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("agent: server certificate fingerprint mismatch")
			}
			return nil
		}
	} else {
		return nil, errors.New("agent: supply --ca <ca.crt> or --ca-fingerprint <sha256>")
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:               rootCAs,
		InsecureSkipVerify:    verify != nil,
		VerifyPeerCertificate: verify,
		MinVersion:            tls.VersionTLS13,
	}}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	payload, _ := json.Marshal(map[string]any{
		"bootstrap_token": opts.BootstrapToken,
		"hostname":        opts.Hostname,
		"role":            opts.Role,
		"csr_pem":         string(csrPEM),
		"agent_version":   Version,
		"tpm_ak_pub":      opts.TPMAKPub,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(opts.ServerURL, "/")+"/api/v1/agent/enroll", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Body: string(raw)}
	}
	var er enrollResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, fmt.Errorf("agent: decode enrolment response: %w", err)
	}
	if er.AgentID == "" || er.CertPEM == "" {
		return nil, errors.New("agent: control plane returned an incomplete identity")
	}

	poll := opts.PollSeconds
	if poll <= 0 {
		poll = 15
	}
	state := &config.AgentState{
		ServerURL:     strings.TrimRight(opts.ServerURL, "/"),
		AgentID:       er.AgentID,
		Role:          opts.Role,
		StateDir:      opts.StateDir,
		CertPEM:       er.CertPEM,
		KeyPEM:        string(keyPEM),
		CACertPEM:     er.CAPEM,
		IssuerPub:     er.AgentConfig["issuer_public_key"],
		PolicyPub:     er.AgentConfig["policy_public_key"],
		ReleasePub:    er.AgentConfig["release_public_key"],
		PublishDir:    opts.PublishDir,
		PollSeconds:   poll,
		PublisherUIDs: opts.PublisherUIDs,
		PublisherSIDs: opts.PublisherSIDs,
		TPMAKCtx:      opts.TPMAKCtx,
		TPMTCTI:       opts.TPMTCTI,
	}
	if err := config.SaveAgentState(opts.StateDir, state); err != nil {
		return nil, err
	}
	return state, nil
}

// Version is the agent build version reported at enrolment.
const Version = "0.2.2"

// serverName extracts a TLS server name from a URL for diagnostics.
func serverName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

var _ = serverName
