// Package config holds on-disk configuration and key material for the
// control plane and agents.
//
// Design rule: secrets never live in the JSON config. The config points at
// PEM files, and every key file is created with 0600.
package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Default locations. These are also what the docs promise.
const (
	DefaultDataDir    = "/var/lib/tamperguard"
	DefaultListenAddr = ":8443"

	// File names inside the data dir.
	ServerConfigFile  = "server.json"
	AgentStateFile    = "agent.json"
	PublishConfigFile = "publish.json"

	KeysDir = "keys"
)

// Key file names inside <dataDir>/keys.
const (
	CACertFile      = "ca.crt"
	CAKeyFile       = "ca.key"
	ServerCertFile  = "server.crt"
	ServerKeyFile   = "server.key"
	TokenSignFile   = "token-signing.key"
	PolicySignFile  = "policy-signing.key"
	IssuerPubFile   = "token-signing.pub"
	PolicyPubFile   = "policy-signing.pub"
	ReleaseSignFile = "release-signing.key"
	ReleasePubFile  = "release-signing.pub"
)

// Server is the control plane configuration stored as <dataDir>/server.json.
type Server struct {
	DataDir           string `json:"data_dir"`
	ListenAddr        string `json:"listen_addr"`
	AdminUser         string `json:"admin_user"`
	AdminPasswordHash string `json:"admin_password_hash"`
	SessionKey        string `json:"session_key"` // base64, 32 bytes
	HeartbeatSeconds  int    `json:"heartbeat_seconds"`
	TokenTTLSeconds   int    `json:"token_ttl_seconds"`
	MaxTokenTTL       int    `json:"max_token_ttl_seconds"`
	// AuditRetentionDays purges audit records older than this many days.
	// Zero keeps everything; the default is "keep", because audit records are
	// evidence.
	AuditRetentionDays int `json:"audit_retention_days"`
}

// DefaultServer returns a config with sane defaults applied.
func DefaultServer(dataDir string) *Server {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return &Server{
		DataDir:          dataDir,
		ListenAddr:       DefaultListenAddr,
		AdminUser:        "admin",
		HeartbeatSeconds: 15,
		TokenTTLSeconds:  300,
		MaxTokenTTL:      900,
	}
}

// SessionKeyBytes decodes the session key, enforcing length.
func (c *Server) SessionKeyBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(c.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("config: session key: %w", err)
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("config: session key too short")
	}
	return b, nil
}

// Path returns a path inside the data directory.
func (c *Server) Path(elem ...string) string {
	return filepath.Join(append([]string{c.DataDir}, elem...)...)
}

// KeyPath returns a path inside <dataDir>/keys.
func (c *Server) KeyPath(name string) string {
	return filepath.Join(c.DataDir, KeysDir, name)
}

// LoadServer reads <dataDir>/server.json.
func LoadServer(dataDir string) (*Server, error) {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, ServerConfigFile))
	if err != nil {
		return nil, fmt.Errorf("config: read server config: %w", err)
	}
	var c Server
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("config: parse server config: %w", err)
	}
	if c.DataDir == "" {
		c.DataDir = dataDir
	}
	if c.HeartbeatSeconds <= 0 {
		c.HeartbeatSeconds = 15
	}
	if c.TokenTTLSeconds <= 0 {
		c.TokenTTLSeconds = 300
	}
	return &c, nil
}

// Save writes the config with 0600.
func SaveServer(c *Server) error {
	if err := os.MkdirAll(c.DataDir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(c.DataDir, ServerConfigFile), b, 0o600)
}

// AgentState is the on-disk state of a protect or publish agent.
type AgentState struct {
	ServerURL   string `json:"server_url"`
	AgentID     string `json:"agent_id"`
	Role        string `json:"role"`
	StateDir    string `json:"state_dir"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"` // never leaves the host
	CACertPEM   string `json:"ca_cert_pem"`
	IssuerPub   string `json:"issuer_public_key"`  // hex
	PolicyPub   string `json:"policy_public_key"`  // hex
	ReleasePub  string `json:"release_public_key"` // hex
	Enforcer    string `json:"enforcer"`
	PolicyID    string `json:"policy_id"`
	PublishDir  string `json:"publish_dir,omitempty"`
	PollSeconds int    `json:"poll_seconds"`
	// PublisherUIDs maps release tokens (which name a publisher identity) onto
	// the operating-system users whose processes may consume a live grant.
	// The kernel cannot see agent identities, only uids.
	PublisherUIDs []int `json:"publisher_uids,omitempty"`
}

// LoadAgentState reads <stateDir>/agent.json.
func LoadAgentState(stateDir string) (*AgentState, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, AgentStateFile))
	if err != nil {
		return nil, fmt.Errorf("config: read agent state: %w", err)
	}
	var s AgentState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("config: parse agent state: %w", err)
	}
	if s.PollSeconds <= 0 {
		s.PollSeconds = 15
	}
	return &s, nil
}

// SaveAgentState writes the state with 0600 (it contains the private key).
func SaveAgentState(stateDir string, s *AgentState) error {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(stateDir, AgentStateFile), b, 0o600)
}

// WriteFileAtomic writes data to a temp file in the same directory and renames
// it into place, so a crash never leaves a truncated key file.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
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
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// WriteEd25519Private stores an Ed25519 private key as PKCS#8 PEM (0600).
func WriteEd25519Private(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// ReadEd25519Private loads a PKCS#8 Ed25519 private key.
func ReadEd25519Private(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("config: %s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("config: %s is not an ed25519 key", path)
	}
	return priv, nil
}

// WriteCertPEM writes a certificate file with 0644.
func WriteCertPEM(path string, der []byte) error {
	return WriteFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
