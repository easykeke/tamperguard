// Package policy holds the protection model shared by the control plane and
// the agents, plus the decision function every enforcer ultimately applies.
//
// The model is intentionally small: a set of protected path rules, each with
// an enforcement mode, and a set of subjects that are allowed to write there.
// Anything not explicitly allowed is denied when the matched rule is in
// enforce mode.
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/easykeke/tamperguard/internal/token"
)

// Mode controls what happens when a protected path is written by a subject
// that is not authorised.
type Mode string

const (
	// ModeEnforce denies the write.
	ModeEnforce Mode = "enforce"
	// ModeObserve allows the write but records it. Used to dry-run a new rule
	// before flipping it to enforce.
	ModeObserve Mode = "observe"
)

// PathRule protects one path. Recursive rules protect a whole subtree;
// non-recursive rules protect exactly one file.
type PathRule struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Mode      Mode   `json:"mode"`
}

// WriterKind distinguishes the two ways a process can earn write permission.
type WriterKind string

const (
	// WriterPublisher is a publishing agent identity (the normal case).
	WriterPublisher WriterKind = "publisher"
	// WriterProcess is a host process allowed to write by binary path and uid.
	// Every use of this kind should be treated as a policy exception and is
	// surfaced separately in the UI.
	WriterProcess WriterKind = "process"
)

// WriterRule authorises one kind of writer.
type WriterRule struct {
	Kind    WriterKind `json:"kind"`
	ID      string     `json:"id,omitempty"`
	ExePath string     `json:"exe_path,omitempty"`
	UID     *int       `json:"uid,omitempty"`
}

// Policy is one immutable version of a protection policy.
type Policy struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Version   int64        `json:"version"`
	Paths     []PathRule   `json:"paths"`
	Writers   []WriterRule `json:"writers"`
	UpdatedAt int64        `json:"updated_at"`
}

// Subject identifies the process attempting a write.
type Subject struct {
	Kind    WriterKind
	ID      string
	ExePath string
	UID     int
	PID     int
}

// Op is the kind of mutating operation being attempted. The kernel enforcer
// maps LSM hooks onto these values.
type Op string

const (
	OpOpenWrite Op = "open_write"
	OpCreate    Op = "create"
	OpUnlink    Op = "unlink"
	OpRename    Op = "rename"
	OpRmdir     Op = "rmdir"
	OpLink      Op = "link"
	OpSetattr   Op = "setattr"
	OpMmapWrite Op = "mmap_write"
)

// Grant is the userspace-validated, currently-live authorisation derived from
// a release token. The kernel only ever sees this reduced form.
type Grant struct {
	TokenID   string   `json:"token_id"`
	Subject   string   `json:"subject"`
	NodeID    string   `json:"node"`
	Paths     []string `json:"paths"`
	ExpiresAt int64    `json:"expires_at"`
}

// Request is one enforcement decision.
type Request struct {
	NodeID   string
	Path     string
	Op       Op
	Subject  Subject
	Grants   []Grant
	Now      int64
	Manifest string
}

// Decision is the outcome, with enough context to write a useful audit record.
type Decision struct {
	Allow  bool
	Mode   Mode
	Rule   string
	Reason string
}

// Stable reason strings. These end up in audit records and alert rules.
const (
	ReasonNotProtected = "not-protected"
	ReasonObserve      = "observe-mode"
	ReasonGranted      = "token-granted"
	ReasonDenied       = "denied"
	ReasonInvalidPath  = "invalid-path"
)

// Validate checks the structural invariants of a policy.
//
// ID is assigned by the store for new policies, so it is not required here;
// everything else must be well formed before the policy can be applied.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy: name is required")
	}
	if len(p.Paths) == 0 {
		return fmt.Errorf("policy: at least one protected path is required")
	}
	for i, r := range p.Paths {
		if _, ok := token.NormalizePath(r.Path); !ok {
			return fmt.Errorf("policy: path[%d] %q must be absolute and clean", i, r.Path)
		}
		switch r.Mode {
		case ModeEnforce, ModeObserve:
		case "":
			p.Paths[i].Mode = ModeEnforce
		default:
			return fmt.Errorf("policy: path[%d] has invalid mode %q", i, r.Mode)
		}
	}
	for i, w := range p.Writers {
		switch w.Kind {
		case WriterPublisher:
			if w.ID == "" {
				return fmt.Errorf("policy: writers[%d] publisher needs an id", i)
			}
		case WriterProcess:
			if w.ExePath == "" {
				return fmt.Errorf("policy: writers[%d] process needs exe_path", i)
			}
			if _, ok := token.NormalizePath(w.ExePath); !ok {
				return fmt.Errorf("policy: writers[%d] exe_path must be absolute", i)
			}
		default:
			return fmt.Errorf("policy: writers[%d] has invalid kind %q", i, w.Kind)
		}
	}
	return nil
}

// Sort normalises slice order so that the digest is stable.
func (p *Policy) Sort() {
	sort.Slice(p.Paths, func(i, j int) bool { return p.Paths[i].Path < p.Paths[j].Path })
	sort.Slice(p.Writers, func(i, j int) bool {
		if p.Writers[i].Kind != p.Writers[j].Kind {
			return p.Writers[i].Kind < p.Writers[j].Kind
		}
		if p.Writers[i].ID != p.Writers[j].ID {
			return p.Writers[i].ID < p.Writers[j].ID
		}
		return p.Writers[i].ExePath < p.Writers[j].ExePath
	})
}

// Digest returns the hex SHA-256 of the canonical policy JSON. Agents pin the
// digest they are enforcing so the server can detect drift.
func (p *Policy) Digest() (string, error) {
	c := *p
	c.Sort()
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("policy: marshal: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// MatchPath returns the most specific rule covering target.
func (p *Policy) MatchPath(target string) (PathRule, bool) {
	tp, ok := token.NormalizePath(target)
	if !ok {
		return PathRule{}, false
	}
	var best PathRule
	found := false
	for _, r := range p.Paths {
		base, ok := token.NormalizePath(r.Path)
		if !ok {
			continue
		}
		covered := tp == base
		if r.Recursive && !covered {
			covered = strings.HasPrefix(tp, base+"/") || base == "/"
		}
		if !covered {
			continue
		}
		if !found || len(base) > len(best.Path) {
			best = r
			found = true
		}
	}
	return best, found
}

// WriterAllowed reports whether s is listed in the policy as a permitted writer.
func (p *Policy) WriterAllowed(s Subject) bool {
	for _, w := range p.Writers {
		switch w.Kind {
		case WriterPublisher:
			if s.Kind == WriterPublisher && s.ID != "" && s.ID == w.ID {
				return true
			}
		case WriterProcess:
			if s.Kind != WriterProcess {
				continue
			}
			if w.ExePath != "" && w.ExePath != s.ExePath {
				continue
			}
			if w.UID != nil && *w.UID != s.UID {
				continue
			}
			return true
		}
	}
	return false
}

// Decide is the single decision function used by every enforcer. It returns
// Allow=true for unprotected paths and for observe-mode rules.
func (p *Policy) Decide(req Request) Decision {
	tp, ok := token.NormalizePath(req.Path)
	if !ok {
		return Decision{Allow: false, Mode: ModeEnforce, Reason: ReasonInvalidPath}
	}
	rule, protected := p.MatchPath(tp)
	if !protected {
		return Decision{Allow: true, Mode: ModeObserve, Reason: ReasonNotProtected}
	}
	if rule.Mode == ModeObserve {
		return Decision{Allow: true, Mode: ModeObserve, Rule: rule.Path, Reason: ReasonObserve}
	}
	if p.WriterAllowed(req.Subject) {
		for _, g := range req.Grants {
			if g.Subject != "" && req.Subject.ID != "" && g.Subject != req.Subject.ID {
				continue
			}
			if g.NodeID != "" && req.NodeID != "" && g.NodeID != req.NodeID {
				continue
			}
			if g.ExpiresAt != 0 && g.ExpiresAt <= req.Now {
				continue
			}
			for _, gp := range g.Paths {
				if token.PathCovered(gp, tp) {
					return Decision{Allow: true, Mode: ModeEnforce, Rule: rule.Path, Reason: ReasonGranted}
				}
			}
		}
	}
	return Decision{Allow: false, Mode: ModeEnforce, Rule: rule.Path, Reason: ReasonDenied}
}

// Snapshot is a signed policy document as delivered to agents.
type Snapshot struct {
	Policy    Policy `json:"policy"`
	Digest    string `json:"digest"`
	IssuedAt  int64  `json:"issued_at"`
	Signature string `json:"signature,omitempty"`
}

// SignSnapshot builds and signs a snapshot with the control-plane policy key.
func SignSnapshot(p Policy, issuedAt int64, priv ed25519.PrivateKey) (*Snapshot, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	d, err := p.Digest()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Policy: p, Digest: d, IssuedAt: issuedAt}
	if len(priv) == ed25519.PrivateKeySize {
		s.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(signatureMessage(s))))
	}
	return s, nil
}

// VerifySnapshot checks the digest and, when pub is provided, the signature.
func (s *Snapshot) Verify(pub ed25519.PublicKey) error {
	d, err := s.Policy.Digest()
	if err != nil {
		return err
	}
	if !strings.EqualFold(d, s.Digest) {
		return fmt.Errorf("policy: snapshot digest mismatch")
	}
	if len(pub) == 0 {
		return nil
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("policy: snapshot signature malformed")
	}
	if !ed25519.Verify(pub, []byte(signatureMessage(s)), sig) {
		return fmt.Errorf("policy: snapshot signature invalid")
	}
	return nil
}

func signatureMessage(s *Snapshot) string {
	return "tg-policy-v1:" + s.Digest
}
