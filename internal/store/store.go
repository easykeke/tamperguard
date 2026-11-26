// Package store is the control plane's persistence layer (SQLite, pure Go).
//
// It is the only package that knows SQL. Everything above it works with the
// structs defined here.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/policy"
)

// ErrNotFound is returned when a lookup misses.
var ErrNotFound = errors.New("store: not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Release is one published agent build.
type Release struct {
	Version     string `json:"version"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	PublishedAt int64  `json:"published_at"`
}

// UpsertRelease records a published build.
func (s *Store) UpsertRelease(r Release) error {
	_, err := s.db.Exec(`INSERT INTO releases (version, os, arch, sha256, size, published_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(version, os, arch) DO UPDATE SET
			sha256=excluded.sha256, size=excluded.size, published_at=excluded.published_at`,
		r.Version, r.OS, r.Arch, r.SHA256, r.Size, r.PublishedAt)
	return err
}

// GetRelease returns one published build.
func (s *Store) GetRelease(version, osName, arch string) (Release, error) {
	var r Release
	err := s.db.QueryRow(`SELECT version, os, arch, sha256, size, published_at
		FROM releases WHERE version=? AND os=? AND arch=?`, version, osName, arch).
		Scan(&r.Version, &r.OS, &r.Arch, &r.SHA256, &r.Size, &r.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	return r, err
}

// LatestRelease returns the newest published build for a platform.
func (s *Store) LatestRelease(osName, arch string) (Release, error) {
	var r Release
	err := s.db.QueryRow(`SELECT version, os, arch, sha256, size, published_at
		FROM releases WHERE os=? AND arch=? ORDER BY published_at DESC LIMIT 1`, osName, arch).
		Scan(&r.Version, &r.OS, &r.Arch, &r.SHA256, &r.Size, &r.PublishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	return r, err
}

// Node is a registered protect or publish agent.
type Node struct {
	ID               string          `json:"id"`
	Hostname         string          `json:"hostname"`
	Role             string          `json:"role"`
	Status           string          `json:"status"`
	Enforcer         string          `json:"enforcer"`
	PolicyID         string          `json:"policy_id"`
	PolicyVersion    int64           `json:"policy_version"`
	PolicyDigest     string          `json:"policy_digest"`
	Degraded         bool            `json:"degraded"`
	DegradedApproved bool            `json:"degraded_approved"`
	Caps             json.RawMessage `json:"caps"`
	AgentVersion     string          `json:"agent_version"`
	LastSeen         int64           `json:"last_seen"`
	EnrolledAt       int64           `json:"enrolled_at"`
	Revoked          bool            `json:"revoked"`
	// ActiveGrants lists the token IDs the agent reported as installed in its
	// enforcement map on the last heartbeat. It is how a publisher can tell
	// that the node is ready for its write, instead of guessing.
	ActiveGrants []string `json:"active_grants"`
	PubKey       string   `json:"-"`
}

// PublishRequest tracks one release, from request to completion.
type PublishRequest struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	PublisherID string `json:"publisher_id"`
	SourceDir   string `json:"source_dir"`
	TargetDir   string `json:"target_dir"`
	Note        string `json:"note"`
	Status      string `json:"status"`
	// Delivery is "local" (publisher writes straight to target_dir) or "pull"
	// (publisher uploads artefacts; the target node's agent fetches and writes).
	Delivery  string `json:"delivery"`
	Manifest  string `json:"manifest"`
	TokenID   string `json:"token_id"`
	Error     string `json:"error"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// PublishFile is one entry of a release manifest stored by the control plane.
type PublishFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Artifact is one uploaded file waiting for a pull delivery.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Delivery modes.
const (
	DeliveryLocal = "local"
	DeliveryPull  = "pull"
)

// Delivery status values that exist only in pull mode.
const (
	PublishDelivering = "delivering"
)

// Publish status values.
const (
	PublishPending   = "pending"
	PublishManifest  = "manifest_received"
	PublishToken     = "token_issued"
	PublishDone      = "done"
	PublishFailed    = "failed"
	PublishCancelled = "cancelled"
)

// TokenRecord is the control plane's view of an issued release token.
type TokenRecord struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	NodeID    string   `json:"node_id"`
	RequestID string   `json:"request_id"`
	Manifest  string   `json:"manifest"`
	Paths     []string `json:"paths"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
	Revoked   bool     `json:"revoked"`
}

// Revocation is one entry of the revocation list.
type Revocation struct {
	ID        int64  `json:"id"`
	Kind      string `json:"kind"` // token | subject | node
	Value     string `json:"value"`
	Reason    string `json:"reason"`
	CreatedAt int64  `json:"created_at"`
}

// Revocation kinds.
const (
	RevokeToken   = "token"
	RevokeSubject = "subject"
	RevokeNode    = "node"
)

// AuditFilter selects audit records.
type AuditFilter struct {
	NodeID    string
	Kind      string
	Limit     int
	BeforeSeq int64
	From      int64 // inclusive, unix seconds
	To        int64 // inclusive, unix seconds
}

// Overview is the dashboard summary.
type Overview struct {
	NodesTotal    int `json:"nodes_total"`
	NodesOnline   int `json:"nodes_online"`
	NodesDegraded int `json:"nodes_degraded"`
	Blocked24h    int `json:"blocked_24h"`
	TokensActive  int `json:"tokens_active"`
	ChainAlerts   int `json:"chain_alerts"`
}

// Open opens or creates the database at path and runs migrations.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite is single-writer; one connection removes an entire class of
	// SQLITE_BUSY bugs at the cost of throughput we do not need yet.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			role TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'offline',
			enforcer TEXT NOT NULL DEFAULT '',
			policy_id TEXT NOT NULL DEFAULT '',
			policy_version INTEGER NOT NULL DEFAULT 0,
			policy_digest TEXT NOT NULL DEFAULT '',
			degraded INTEGER NOT NULL DEFAULT 0,
			degraded_approved INTEGER NOT NULL DEFAULT 0,
			caps TEXT NOT NULL DEFAULT '{}',
			agent_version TEXT NOT NULL DEFAULT '',
			last_seen INTEGER NOT NULL DEFAULT 0,
			enrolled_at INTEGER NOT NULL DEFAULT 0,
			revoked INTEGER NOT NULL DEFAULT 0,
			pubkey TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			version INTEGER NOT NULL,
			doc TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_policy (
			node_id TEXT PRIMARY KEY,
			policy_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS publish_requests (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			publisher_id TEXT NOT NULL,
			source_dir TEXT NOT NULL DEFAULT '',
			target_dir TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			manifest TEXT NOT NULL DEFAULT '',
			token_id TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_by TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			subject TEXT NOT NULL,
			node_id TEXT NOT NULL,
			request_id TEXT NOT NULL DEFAULT '',
			manifest TEXT NOT NULL DEFAULT '',
			paths TEXT NOT NULL DEFAULT '[]',
			issued_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS revocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind TEXT NOT NULL,
			value TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			UNIQUE(kind, value)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_records (
			agent_id TEXT NOT NULL,
			seq INTEGER NOT NULL,
			ts INTEGER NOT NULL,
			kind TEXT NOT NULL,
			decision TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			op TEXT NOT NULL DEFAULT '',
			subject TEXT NOT NULL DEFAULT '',
			token_id TEXT NOT NULL DEFAULT '',
			prev_hash TEXT NOT NULL,
			hash TEXT NOT NULL,
			sig TEXT NOT NULL,
			raw TEXT NOT NULL,
			PRIMARY KEY (agent_id, seq)
		)`,
		`CREATE TABLE IF NOT EXISTS chain_state (
			agent_id TEXT PRIMARY KEY,
			next_seq INTEGER NOT NULL,
			last_hash TEXT NOT NULL DEFAULT '',
			alert TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS bootstrap_tokens (
			hash TEXT PRIMARY KEY,
			role TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			used_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS releases (
			version TEXT NOT NULL,
			os TEXT NOT NULL,
			arch TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			published_at INTEGER NOT NULL,
			PRIMARY KEY (version, os, arch)
		)`,
		`CREATE TABLE IF NOT EXISTS publish_files (
			request_id TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			PRIMARY KEY (request_id, path)
		)`,
		`CREATE TABLE IF NOT EXISTS publish_artifacts (
			request_id TEXT NOT NULL,
			path TEXT NOT NULL,
			sha256 TEXT NOT NULL,
			size INTEGER NOT NULL,
			PRIMARY KEY (request_id, path)
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	// Additive migrations for databases created by an older build. SQLite has
	// no "ADD COLUMN IF NOT EXISTS", so a duplicate-column error is expected
	// and ignored.
	additive := []string{
		`ALTER TABLE nodes ADD COLUMN active_grants TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE publish_requests ADD COLUMN delivery TEXT NOT NULL DEFAULT 'local'`,
	}
	for _, q := range additive {
		if _, err := s.db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("store: migrate (additive): %w", err)
		}
	}
	return nil
}

func now() int64 { return time.Now().Unix() }

// ---------- nodes ----------

// UpsertNode inserts or updates a node identity (on enrollment).
func (s *Store) UpsertNode(n Node) error {
	_, err := s.db.Exec(`INSERT INTO nodes
		(id, hostname, role, status, enforcer, caps, agent_version, last_seen, enrolled_at, pubkey)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname, role=excluded.role, status=excluded.status,
			enforcer=excluded.enforcer, caps=excluded.caps,
			agent_version=excluded.agent_version, last_seen=excluded.last_seen,
			pubkey=excluded.pubkey, revoked=0`,
		n.ID, n.Hostname, n.Role, n.Status, n.Enforcer, string(n.Caps), n.AgentVersion, now(), now(), n.PubKey)
	return err
}

const nodeCols = `id, hostname, role, status, enforcer, policy_id, policy_version, policy_digest,
	degraded, degraded_approved, caps, agent_version, last_seen, enrolled_at, revoked, active_grants, pubkey`

func scanNode(sc interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var caps, activeGrants string
	var degraded, approved, revoked int
	err := sc.Scan(&n.ID, &n.Hostname, &n.Role, &n.Status, &n.Enforcer, &n.PolicyID,
		&n.PolicyVersion, &n.PolicyDigest, &degraded, &approved, &caps,
		&n.AgentVersion, &n.LastSeen, &n.EnrolledAt, &revoked, &activeGrants, &n.PubKey)
	if err != nil {
		return Node{}, err
	}
	n.Degraded = degraded != 0
	n.DegradedApproved = approved != 0
	n.Revoked = revoked != 0
	if caps == "" {
		caps = "{}"
	}
	n.Caps = json.RawMessage(caps)
	if activeGrants != "" {
		if err := json.Unmarshal([]byte(activeGrants), &n.ActiveGrants); err != nil {
			n.ActiveGrants = nil
		}
	}
	if n.Role == "" {
		n.Role = "protect"
	}
	return n, nil
}

// GetNode returns one node.
func (s *Store) GetNode(id string) (Node, error) {
	row := s.db.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// ListNodes returns every node, protect and publish.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT ` + nodeCols + ` FROM nodes ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// HeartbeatInput is what an agent reports on every heartbeat.
type HeartbeatInput struct {
	NodeID          string
	Status          string
	Enforcer        string
	PolicyDigest    string
	Caps            json.RawMessage
	Degraded        bool
	AgentVersion    string
	EnforcerHealthy bool
}

// ApplyHeartbeat updates liveness and reported state.
func (s *Store) ApplyHeartbeat(h HeartbeatInput) error {
	if len(h.Caps) == 0 {
		h.Caps = json.RawMessage("{}")
	}
	status := h.Status
	if status == "" {
		status = "online"
	}
	_, err := s.db.Exec(`UPDATE nodes SET status=?, enforcer=?, policy_digest=?,
		caps=?, degraded=?, agent_version=?, last_seen=? WHERE id=?`,
		status, h.Enforcer, h.PolicyDigest, string(h.Caps), boolInt(h.Degraded), h.AgentVersion, now(), h.NodeID)
	return err
}

// SetNodePolicy records which policy version a node is enforcing.
func (s *Store) SetNodePolicy(nodeID, policyID string, version int64, digest string) error {
	if _, err := s.db.Exec(`UPDATE nodes SET policy_id=?, policy_version=?, policy_digest=? WHERE id=?`,
		policyID, version, digest, nodeID); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO node_policy (node_id, policy_id) VALUES (?,?)
		ON CONFLICT(node_id) DO UPDATE SET policy_id=excluded.policy_id`, nodeID, policyID)
	return err
}

// AssignPolicy binds a node to a policy without touching its reported state.
func (s *Store) AssignPolicy(nodeID, policyID string) error {
	if _, err := s.db.Exec(`INSERT INTO node_policy (node_id, policy_id) VALUES (?,?)
		ON CONFLICT(node_id) DO UPDATE SET policy_id=excluded.policy_id`, nodeID, policyID); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE nodes SET policy_id=? WHERE id=?`, policyID, nodeID)
	return err
}

// PolicyIDForNode returns the policy bound to a node, if any.
func (s *Store) PolicyIDForNode(nodeID string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT policy_id FROM node_policy WHERE node_id=?`, nodeID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// ApproveDegraded records an administrator's explicit acceptance of a
// degraded (i.e. weaker) protection mode for a node.
func (s *Store) ApproveDegraded(nodeID string, approved bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET degraded_approved=? WHERE id=?`, boolInt(approved), nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeActiveGrants records the token IDs the agent has installed.
func (s *Store) SetNodeActiveGrants(nodeID string, ids []string) error {
	if ids == nil {
		ids = []string{}
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE nodes SET active_grants=? WHERE id=?`, string(b), nodeID)
	return err
}

// NodeHasActiveGrant reports whether a node reported the given token as
// installed.
func (s *Store) NodeHasActiveGrant(nodeID, tokenID string) (bool, error) {
	n, err := s.GetNode(nodeID)
	if err != nil {
		return false, err
	}
	for _, id := range n.ActiveGrants {
		if id == tokenID {
			return true, nil
		}
	}
	return false, nil
}

// SetNodeRevoked marks a node identity as revoked (its cert is rejected).
func (s *Store) SetNodeRevoked(nodeID string, revoked bool) error {
	res, err := s.db.Exec(`UPDATE nodes SET revoked=? WHERE id=?`, boolInt(revoked), nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- policies ----------

// CreatePolicy stores a new policy version 1.
func (s *Store) CreatePolicy(p policy.Policy) (policy.Policy, error) {
	if p.ID == "" {
		p.ID = idgen.New("pol_")
	}
	p.Version = 1
	p.UpdatedAt = now()
	doc, err := json.Marshal(p)
	if err != nil {
		return policy.Policy{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO policies (id, name, version, doc, updated_at) VALUES (?,?,?,?,?)`,
		p.ID, p.Name, p.Version, string(doc), p.UpdatedAt); err != nil {
		return policy.Policy{}, err
	}
	return p, nil
}

// UpdatePolicy replaces a policy and bumps its version.
func (s *Store) UpdatePolicy(p policy.Policy) (policy.Policy, error) {
	cur, err := s.GetPolicy(p.ID)
	if err != nil {
		return policy.Policy{}, err
	}
	p.Version = cur.Version + 1
	p.UpdatedAt = now()
	doc, err := json.Marshal(p)
	if err != nil {
		return policy.Policy{}, err
	}
	if _, err := s.db.Exec(`UPDATE policies SET name=?, version=?, doc=?, updated_at=? WHERE id=?`,
		p.Name, p.Version, string(doc), p.UpdatedAt, p.ID); err != nil {
		return policy.Policy{}, err
	}
	return p, nil
}

// GetPolicy loads one policy.
func (s *Store) GetPolicy(id string) (policy.Policy, error) {
	var doc string
	err := s.db.QueryRow(`SELECT doc FROM policies WHERE id=?`, id).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.Policy{}, ErrNotFound
	}
	if err != nil {
		return policy.Policy{}, err
	}
	var p policy.Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return policy.Policy{}, err
	}
	return p, nil
}

// ListPolicies returns all policies.
func (s *Store) ListPolicies() ([]policy.Policy, error) {
	rows, err := s.db.Query(`SELECT doc FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []policy.Policy
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var p policy.Policy
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePolicy removes a policy that is not assigned to any node.
func (s *Store) DeletePolicy(id string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM node_policy WHERE policy_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("store: policy assigned to %d node(s)", n)
	}
	_, err := s.db.Exec(`DELETE FROM policies WHERE id=?`, id)
	return err
}

// ---------- publish requests ----------

// CreatePublishRequest inserts a pending release request.
func (s *Store) CreatePublishRequest(r PublishRequest) (PublishRequest, error) {
	if r.ID == "" {
		r.ID = idgen.New("pr_")
	}
	r.Status = PublishPending
	if r.Delivery == "" {
		r.Delivery = DeliveryLocal
	}
	r.CreatedAt = now()
	r.UpdatedAt = r.CreatedAt
	_, err := s.db.Exec(`INSERT INTO publish_requests
		(id, node_id, publisher_id, source_dir, target_dir, note, status, delivery, created_by, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.NodeID, r.PublisherID, r.SourceDir, r.TargetDir, r.Note, r.Status, r.Delivery, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return r, err
}

const publishCols = `id, node_id, publisher_id, source_dir, target_dir, note, status, delivery, manifest, token_id, error, created_by, created_at, updated_at`

func scanPublish(sc interface{ Scan(...any) error }) (PublishRequest, error) {
	var r PublishRequest
	err := sc.Scan(&r.ID, &r.NodeID, &r.PublisherID, &r.SourceDir, &r.TargetDir, &r.Note, &r.Status,
		&r.Delivery, &r.Manifest, &r.TokenID, &r.Error, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// GetPublishRequest loads one request.
func (s *Store) GetPublishRequest(id string) (PublishRequest, error) {
	row := s.db.QueryRow(`SELECT `+publishCols+` FROM publish_requests WHERE id=?`, id)
	r, err := scanPublish(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PublishRequest{}, ErrNotFound
	}
	return r, err
}

// ListPublishRequests returns requests, newest first, optionally by status.
func (s *Store) ListPublishRequests(status string, limit int) ([]PublishRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + publishCols + ` FROM publish_requests`
	args := []any{}
	if status != "" {
		q += ` WHERE status=?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishRequest
	for rows.Next() {
		r, err := scanPublish(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListPendingForPublisher returns pending requests assigned to one publisher.
func (s *Store) ListPendingForPublisher(publisherID string) ([]PublishRequest, error) {
	rows, err := s.db.Query(`SELECT `+publishCols+` FROM publish_requests
		WHERE publisher_id=? AND status IN (?,?) ORDER BY created_at LIMIT 50`,
		publisherID, PublishPending, PublishManifest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishRequest
	for rows.Next() {
		r, err := scanPublish(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdatePublishRequest mutates a request's status and side fields.
func (s *Store) UpdatePublishRequest(id, status, manifest, tokenID, errMsg string) error {
	_, err := s.db.Exec(`UPDATE publish_requests SET status=?, manifest=?, token_id=?, error=?, updated_at=? WHERE id=?`,
		status, manifest, tokenID, errMsg, now(), id)
	return err
}

// SetPublishFiles replaces the manifest file list for a request.
func (s *Store) SetPublishFiles(requestID string, files []PublishFile) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM publish_files WHERE request_id=?`, requestID); err != nil {
		return err
	}
	for _, f := range files {
		if _, err := tx.Exec(`INSERT INTO publish_files (request_id, path, sha256, size) VALUES (?,?,?,?)`,
			requestID, f.Path, f.SHA256, f.Size); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListPublishFiles returns the manifest file list for a request.
func (s *Store) ListPublishFiles(requestID string) ([]PublishFile, error) {
	rows, err := s.db.Query(`SELECT path, sha256, size FROM publish_files WHERE request_id=? ORDER BY path`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishFile
	for rows.Next() {
		var f PublishFile
		if err := rows.Scan(&f.Path, &f.SHA256, &f.Size); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecordArtifact records an uploaded file for a pull-mode request.
func (s *Store) RecordArtifact(requestID string, a Artifact) error {
	_, err := s.db.Exec(`INSERT INTO publish_artifacts (request_id, path, sha256, size) VALUES (?,?,?,?)
		ON CONFLICT(request_id, path) DO UPDATE SET sha256=excluded.sha256, size=excluded.size`,
		requestID, a.Path, a.SHA256, a.Size)
	return err
}

// GetArtifact returns one uploaded artefact record.
func (s *Store) GetArtifact(requestID, path string) (Artifact, error) {
	var a Artifact
	err := s.db.QueryRow(`SELECT path, sha256, size FROM publish_artifacts WHERE request_id=? AND path=?`,
		requestID, path).Scan(&a.Path, &a.SHA256, &a.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	return a, err
}

// ListArtifacts returns all uploaded artefacts for a request.
func (s *Store) ListArtifacts(requestID string) ([]Artifact, error) {
	rows, err := s.db.Query(`SELECT path, sha256, size FROM publish_artifacts WHERE request_id=? ORDER BY path`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.Path, &a.SHA256, &a.Size); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListPullDeliveriesForNode returns pull-mode requests waiting for this node.
func (s *Store) ListPullDeliveriesForNode(nodeID string) ([]PublishRequest, error) {
	rows, err := s.db.Query(`SELECT `+publishCols+` FROM publish_requests
		WHERE node_id=? AND delivery=? AND status IN (?,?) ORDER BY created_at LIMIT 20`,
		nodeID, DeliveryPull, PublishToken, PublishDelivering)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublishRequest
	for rows.Next() {
		r, err := scanPublish(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClaimPublishDelivery atomically moves a request into "delivering" so that two
// agents cannot deliver the same release twice.
func (s *Store) ClaimPublishDelivery(id, nodeID string) (bool, error) {
	res, err := s.db.Exec(`UPDATE publish_requests SET status=?, updated_at=?
		WHERE id=? AND node_id=? AND delivery=? AND status=?`,
		PublishDelivering, now(), id, nodeID, DeliveryPull, PublishToken)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LatestCompletedPublishForNode returns the newest completed pull-mode release
// for a node. Local-mode releases leave no artefacts on the control plane, so
// the signed site manifest only exists for pull deliveries.
func (s *Store) LatestCompletedPublishForNode(nodeID string) (PublishRequest, error) {
	row := s.db.QueryRow(`SELECT `+publishCols+` FROM publish_requests
		WHERE node_id=? AND status=? AND delivery=? ORDER BY updated_at DESC LIMIT 1`,
		nodeID, PublishDone, DeliveryPull)
	r, err := scanPublish(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PublishRequest{}, ErrNotFound
	}
	return r, err
}

// ---------- tokens ----------

// InsertToken records an issued token.
func (s *Store) InsertToken(t TokenRecord) error {
	paths, _ := json.Marshal(t.Paths)
	_, err := s.db.Exec(`INSERT INTO tokens (id, subject, node_id, request_id, manifest, paths, issued_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		t.ID, t.Subject, t.NodeID, t.RequestID, t.Manifest, string(paths), t.IssuedAt, t.ExpiresAt)
	return err
}

// ListTokens returns the newest tokens.
func (s *Store) ListTokens(limit int) ([]TokenRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, subject, node_id, request_id, manifest, paths, issued_at, expires_at, revoked
		FROM tokens ORDER BY issued_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRecord
	for rows.Next() {
		var t TokenRecord
		var paths string
		var revoked int
		if err := rows.Scan(&t.ID, &t.Subject, &t.NodeID, &t.RequestID, &t.Manifest, &paths, &t.IssuedAt, &t.ExpiresAt, &revoked); err != nil {
			return nil, err
		}
		t.Revoked = revoked != 0
		if err := json.Unmarshal([]byte(paths), &t.Paths); err != nil && paths != "" {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkTokenRevoked flips the revoked flag.
func (s *Store) MarkTokenRevoked(id string) error {
	_, err := s.db.Exec(`UPDATE tokens SET revoked=1 WHERE id=?`, id)
	return err
}

// ---------- revocations ----------

// AddRevocation appends a revocation (idempotent on kind+value).
func (s *Store) AddRevocation(kind, value, reason string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO revocations (kind, value, reason, created_at) VALUES (?,?,?,?)`,
		kind, value, reason, now())
	return err
}

// ListRevocations returns all revocations, newest first.
func (s *Store) ListRevocations() ([]Revocation, error) {
	rows, err := s.db.Query(`SELECT id, kind, value, reason, created_at FROM revocations ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.ID, &r.Kind, &r.Value, &r.Reason, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- audit ----------

// AppendAudit stores a verified batch and advances the agent's chain state
// atomically. Callers must have verified the records first.
func (s *Store) AppendAudit(agentID string, recs []audit.Record, nextSeq uint64, lastHash string) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range recs {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO audit_records
			(agent_id, seq, ts, kind, decision, path, op, subject, token_id, prev_hash, hash, sig, raw)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			agentID, r.Seq, r.Time, r.Kind, r.Decision, r.Path, r.Op, r.Subject, r.TokenID,
			r.PrevHash, r.Hash, r.Sig, string(raw)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO chain_state (agent_id, next_seq, last_hash, alert, updated_at)
		VALUES (?,?,?,'',?)
		ON CONFLICT(agent_id) DO UPDATE SET next_seq=excluded.next_seq, last_hash=excluded.last_hash, updated_at=excluded.updated_at`,
		agentID, nextSeq, lastHash, now()); err != nil {
		return err
	}
	return tx.Commit()
}

// SetChainAlert records a chain integrity problem for an agent.
func (s *Store) SetChainAlert(agentID, alert string) error {
	_, err := s.db.Exec(`INSERT INTO chain_state (agent_id, next_seq, last_hash, alert, updated_at)
		VALUES (?,1,'',?,?)
		ON CONFLICT(agent_id) DO UPDATE SET alert=excluded.alert, updated_at=excluded.updated_at`,
		agentID, alert, now())
	return err
}

// ChainStateRow is the per-agent chain tracking state.
type ChainStateRow struct {
	AgentID  string `json:"agent_id"`
	NextSeq  uint64 `json:"next_seq"`
	LastHash string `json:"last_hash"`
	Alert    string `json:"alert"`
	Updated  int64  `json:"updated_at"`
}

// GetChainState returns one agent's chain state.
func (s *Store) GetChainState(agentID string) (ChainStateRow, error) {
	var c ChainStateRow
	err := s.db.QueryRow(`SELECT agent_id, next_seq, last_hash, alert, updated_at FROM chain_state WHERE agent_id=?`, agentID).
		Scan(&c.AgentID, &c.NextSeq, &c.LastHash, &c.Alert, &c.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ChainStateRow{AgentID: agentID, NextSeq: 1}, nil
	}
	return c, err
}

// ListChainStates returns all chain states with an alert, plus all agents.
func (s *Store) ListChainStates() ([]ChainStateRow, error) {
	rows, err := s.db.Query(`SELECT agent_id, next_seq, last_hash, alert, updated_at FROM chain_state ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChainStateRow
	for rows.Next() {
		var c ChainStateRow
		if err := rows.Scan(&c.AgentID, &c.NextSeq, &c.LastHash, &c.Alert, &c.Updated); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PurgeAuditBefore deletes audit records older than cutoff and returns how many
// rows were removed.
func (s *Store) PurgeAuditBefore(cutoff int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_records WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListAudit returns records newest first.
func (s *Store) ListAudit(f AuditFilter) ([]audit.Record, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	q := `SELECT raw FROM audit_records WHERE 1=1`
	args := []any{}
	if f.NodeID != "" {
		q += ` AND agent_id=?`
		args = append(args, f.NodeID)
	}
	if f.Kind != "" {
		q += ` AND kind=?`
		args = append(args, f.Kind)
	}
	if f.BeforeSeq > 0 {
		q += ` AND seq<?`
		args = append(args, f.BeforeSeq)
	}
	if f.From > 0 {
		q += ` AND ts>=?`
		args = append(args, f.From)
	}
	if f.To > 0 {
		q += ` AND ts<=?`
		args = append(args, f.To)
	}
	q += ` ORDER BY agent_id, seq DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Record
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditForAgent returns all stored records for one agent in sequence order.
func (s *Store) AuditForAgent(agentID string) ([]audit.Record, error) {
	rows, err := s.db.Query(`SELECT raw FROM audit_records WHERE agent_id=? ORDER BY seq`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Record
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- bootstrap tokens ----------

// AddBootstrapToken stores a hashed one-time enrollment token.
func (s *Store) AddBootstrapToken(hash, role string) error {
	_, err := s.db.Exec(`INSERT INTO bootstrap_tokens (hash, role, created_at) VALUES (?,?,?)`, hash, role, now())
	return err
}

// ConsumeBootstrapToken marks a token used and returns its role.
func (s *Store) ConsumeBootstrapToken(hash string) (string, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	var role string
	var used int64
	err = tx.QueryRow(`SELECT role, used_at FROM bootstrap_tokens WHERE hash=?`, hash).Scan(&role, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if used != 0 {
		return "", false, nil
	}
	if _, err := tx.Exec(`UPDATE bootstrap_tokens SET used_at=? WHERE hash=?`, now(), hash); err != nil {
		return "", false, err
	}
	return role, true, tx.Commit()
}

// ---------- overview ----------

// Overview computes dashboard counters. onlineWindow is in seconds.
func (s *Store) Overview(onlineWindow int64) (Overview, error) {
	var o Overview
	cutoff := now() - onlineWindow
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE role='protect' AND revoked=0`).Scan(&o.NodesTotal); err != nil {
		return o, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE role='protect' AND revoked=0 AND last_seen>?`, cutoff).Scan(&o.NodesOnline); err != nil {
		return o, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE role='protect' AND revoked=0 AND degraded=1`).Scan(&o.NodesDegraded); err != nil {
		return o, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_records WHERE kind=? AND ts>?`, audit.KindWriteBlocked, now()-86400).Scan(&o.Blocked24h); err != nil {
		return o, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE revoked=0 AND expires_at>?`, now()).Scan(&o.TokensActive); err != nil {
		return o, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM chain_state WHERE alert<>''`).Scan(&o.ChainAlerts); err != nil {
		return o, err
	}
	return o, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
