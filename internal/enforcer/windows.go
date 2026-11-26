//go:build windows

package enforcer

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/baseline"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/token"
	"github.com/easykeke/tamperguard/internal/watch"
)

// WindowsACL is the Windows enforcement backend.
//
// Windows has no eBPF LSM or fanotify equivalent; a real kernel-level blocker
// would be a signed filesystem minifilter. Without a driver, the strongest
// option is the NTFS access control model itself:
//
//   - every protected path gets an explicit DACL: SYSTEM and Administrators
//     full control, Everyone read+execute only;
//   - a live release grant temporarily adds a write+delete ACE for the
//     configured publisher accounts, inherited into the subtree;
//   - the ACE is removed when the token expires or is revoked.
//
// This blocks at open time for any account that is not an administrator, which
// covers the web-defacement threat (IIS worker processes, upload handlers).
// It is reported as degraded because: administrators bypass it, handles that
// were already open are unaffected, and the OS gives no per-write events for
// auditing.
type WindowsACL struct {
	log    *slog.Logger
	state  string
	sids   []*windows.SID
	events *Buffer

	mic         bool
	micErr      error
	allowAdmins bool
	idleLevel   integrityLevel

	// self-heal baseline
	base           *baseline.Manager
	scanInterval   time.Duration
	snapshotted    bool
	needResnapshot bool
	policyDigest   string
	healMu         sync.Mutex
	recent         map[string]int64
	scanSignal     chan struct{}
	watchMu        sync.Mutex
	watchers       []watch.Watcher

	mu      sync.Mutex
	rt      Runtime
	applied map[string]string // normalized path -> native path
	health  error
	stop    chan struct{}
	once    sync.Once
}

// WindowsACLConfig configures the backend.
type WindowsACLConfig struct {
	// PublisherSIDs are the accounts allowed to write during a release window.
	PublisherSIDs []string
	// StateDir stores the list of locked paths for `tg-agent unlock`.
	StateDir string
	// IntegrityLevel selects the mandatory label used while idle: "system"
	// (strongest; the agent must run as a SYSTEM service to set it), "high",
	// "medium" or "off". Requesting a level above the agent's own token level is
	// downgraded with a warning, because Windows does not allow labelling an
	// object above the caller's integrity.
	IntegrityLevel string
	// AllowAdmins keeps an explicit "Administrators: full control" ACE. It is
	// off by default: tamper protection is pointless if any admin process can
	// simply write the file. Turn it on only for appliances whose operations
	// tooling runs as an administrator and cannot be moved to a service account.
	AllowAdmins bool
}

// NewWindowsACL builds the backend.
func NewWindowsACL(cfg WindowsACLConfig) (*WindowsACL, error) {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return nil, errors.New("windows-acl: the agent must run elevated (Administrator or SYSTEM)")
	}
	w := &WindowsACL{
		log:         slog.Default(),
		state:       cfg.StateDir,
		events:      NewBuffer(128),
		allowAdmins: cfg.AllowAdmins,
		applied:     map[string]string{},
		stop:        make(chan struct{}),
	}
	level, levelOK := parseLevel(cfg.IntegrityLevel)
	if !levelOK {
		return nil, fmt.Errorf("windows-acl: unknown integrity level %q", cfg.IntegrityLevel)
	}
	if level != levelUnknown {
		if err := enablePrivilege("SeSecurityPrivilege"); err != nil {
			w.micErr = err
			w.log.Warn("windows-acl: MIC disabled (cannot enable SeSecurityPrivilege)", "err", err)
		} else {
			w.mic = true
			if tok := currentTokenIntegrity(); tok != levelUnknown && level > tok {
				w.log.Warn("windows-acl: requested integrity level is above the agent token; downgrading (run the agent as a SYSTEM service for full strength)",
					"requested", levelName(level), "token", levelName(tok))
				level = tok
			}
			w.idleLevel = level
		}
	}
	for _, raw := range cfg.PublisherSIDs {
		sid, err := resolveSID(raw)
		if err != nil {
			w.log.Warn("windows-acl: cannot resolve publisher account", "account", raw, "err", err)
			continue
		}
		w.sids = append(w.sids, sid)
	}
	if err := w.setupSelfHeal(cfg.StateDir); err != nil {
		w.log.Warn("windows-acl: self-heal disabled (baseline unavailable)", "err", err)
	}
	go w.expiryLoop()
	return w, nil
}

// Name implements Enforcer.
func (w *WindowsACL) Name() string { return "windows-acl" }

// Capability implements Enforcer.
func (w *WindowsACL) Capability() Capability {
	reason := "ACL lockdown: only SYSTEM (and configured publisher accounts during a release window) may write; administrators are not granted write access"
	if !w.allowAdmins {
		reason += " (strict mode; owners can still take ownership and rewrite the DACL)"
	} else {
		reason += " (administrators explicitly allowed)"
	}
	if w.mic {
		reason += fmt.Sprintf("; MIC: protected paths are labelled %s with NO_WRITE_UP, so processes below that level (including elevated administrators when the level is System) are denied writes as well", levelName(w.idleLevel))
	}
	reason += "; a determined administrator can still stop the agent or retake ownership, which is why audit evidence exists"
	if w.base != nil {
		reason += "; self-heal: the protected tree is compared against a content-addressed baseline every " +
			w.scanInterval.String() + " and unauthorised changes are reverted (tamper.restored)"
	}
	return Capability{
		Kind:      "windows-acl",
		Available: true,
		Degraded:  true,
		Reason:    reason,
	}
}

// Update applies the DACL for every enforce-mode rule, with live grants folded
// in.
func (w *WindowsACL) Update(rt Runtime) error {
	w.mu.Lock()
	w.rt = rt
	w.mu.Unlock()

	if rt.Policy == nil {
		return nil
	}
	now := time.Now().Unix()
	var errs []string
	var micErrs []string
	applied := map[string]string{}

	for _, rule := range rt.Policy.Policy.Paths {
		if rule.Mode != policy.ModeEnforce {
			continue
		}
		norm, ok := normalizeRulePath(rule.Path)
		if !ok {
			errs = append(errs, "invalid path "+rule.Path)
			continue
		}
		native := nativePath(norm)
		info, err := os.Stat(native)
		if err != nil {
			// A protected path that does not exist yet is not an error; the
			// policy will be applied once it appears.
			continue
		}
		entries := w.buildEntries(rt, norm, info.IsDir(), now)
		if err := applyDACL(native, entries, info.IsDir()); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", native, err))
			continue
		}
		if w.mic {
			// Configured idle level (System when the agent runs as SYSTEM, High
			// when it runs as an elevated administrator). During a live grant the
			// label drops to Medium so the publisher account can write through
			// the DACL grant, then returns to the idle level.
			level := w.idleLevel
			if w.grantCovers(rt, norm, now) && level > levelMedium {
				level = levelMedium
			}
			if err := setIntegrity(native, level, info.IsDir()); err != nil {
				micErrs = append(micErrs, fmt.Sprintf("%s (MIC): %v", native, err))
			}
		}
		applied[norm] = native
	}

	if w.base != nil {
		w.maybeSnapshot(rt, now)
	}

	w.mu.Lock()
	w.applied = applied
	allErrs := append(append([]string{}, errs...), micErrs...)
	if len(allErrs) > 0 {
		w.health = errors.New(strings.Join(allErrs, "; "))
	} else {
		w.health = nil
	}
	w.mu.Unlock()

	// Persist the roots even when some checks failed: `unlock` must be able to
	// clean up whatever was applied.
	if err := w.saveRoots(applied); err != nil {
		w.log.Warn("windows-acl: cannot persist applied roots", "err", err)
	}
	if len(allErrs) > 0 {
		w.log.Error("windows-acl: some paths could not be locked", "errors", strings.Join(allErrs, "; "))
		w.events.Emit(Event{Time: now, Kind: audit.KindEnforcerError, Reason: strings.Join(allErrs, "; ")})
		return nil
	}
	w.events.Emit(Event{Time: now, Kind: audit.KindPolicyApplied, Reason: fmt.Sprintf("acl applied to %d paths", len(applied))})
	return nil
}

// buildEntries builds the explicit DACL for one path: lockdown rights plus, for
// paths covered by a live grant, the publisher write rights.
func (w *WindowsACL) buildEntries(rt Runtime, normPath string, isDir bool, now int64) []windows.EXPLICIT_ACCESS {
	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		makeEntry(windows.GENERIC_ALL, inherit, mustWellKnown(windows.WinLocalSystemSid)),
	}
	// Strict mode: administrators keep only the rights needed to maintain the
	// security descriptor (and to let the agent, which may run as an elevated
	// administrator rather than SYSTEM, re-apply the lockdown). They cannot
	// write file data, and MIC still blocks them at the System integrity label.
	adminMask := windows.ACCESS_MASK(windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER)
	if w.allowAdmins {
		adminMask = windows.GENERIC_ALL
	}
	entries = append(entries, makeEntry(adminMask, inherit,
		mustWellKnown(windows.WinBuiltinAdministratorsSid)))
	entries = append(entries, makeEntry(windows.GENERIC_READ|windows.GENERIC_EXECUTE, inherit,
		mustWellKnown(windows.WinWorldSid)))
	if w.grantCovers(rt, normPath, now) {
		for _, sid := range w.sids {
			entries = append(entries, makeEntry(
				windows.GENERIC_READ|windows.GENERIC_WRITE|windows.GENERIC_EXECUTE|windows.DELETE,
				inherit, sid))
		}
	}
	return entries
}

func (w *WindowsACL) grantCovers(rt Runtime, normPath string, now int64) bool {
	for _, g := range rt.ValidGrants("", "", now) {
		for _, p := range g.Paths {
			if gp, ok := normalizeRulePath(p); ok && pathCoveredNorm(gp, normPath) {
				return true
			}
		}
	}
	return false
}

func normalizeOnWindows(p string) (string, bool) { return token.NormalizePath(p) }

func pathCoveredNorm(base, target string) bool { return token.PathCovered(base, target) }

// normFromNative converts a native Windows path back to the slash spelling used
// by the shared model.
func normFromNative(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func makeEntry(mask windows.ACCESS_MASK, inherit uint32, sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValue(unsafe.Pointer(sid)),
		},
	}
}

var wellKnown = map[windows.WELL_KNOWN_SID_TYPE]*windows.SID{}

func mustWellKnown(kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	if sid, ok := wellKnown[kind]; ok {
		return sid
	}
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		// The well-known SIDs below always exist on Windows.
		panic("windows-acl: cannot create well-known SID: " + err.Error())
	}
	wellKnown[kind] = sid
	return sid
}

func resolveSID(account string) (*windows.SID, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, errors.New("empty account")
	}
	if strings.HasPrefix(strings.ToUpper(account), "S-1-") {
		return windows.StringToSid(account)
	}
	return lookupAccount(account)
}

// lookupAccount resolves a local or domain account name to an SID. The SID is
// copied out of the stack buffer so it stays valid after this function returns.
func lookupAccount(name string) (*windows.SID, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sidBuf [256]byte
	sidLen := uint32(len(sidBuf))
	var domain [256]uint16
	domainLen := uint32(len(domain))
	var use uint32
	if err := windows.LookupAccountName(nil, namePtr,
		(*windows.SID)(unsafe.Pointer(&sidBuf[0])), &sidLen,
		&domain[0], &domainLen, &use); err != nil {
		return nil, err
	}
	out := make([]byte, sidLen)
	copy(out, sidBuf[:sidLen])
	return (*windows.SID)(unsafe.Pointer(&out[0])), nil
}

// applyDACL sets an explicit DACL. Protected means the path stops inheriting
// from its parent, so the lockdown cannot be undone by a permissive parent.
func applyDACL(native string, entries []windows.EXPLICIT_ACCESS, protect bool) error {
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protect {
		info |= windows.SECURITY_INFORMATION(windows.PROTECTED_DACL_SECURITY_INFORMATION)
	} else {
		info |= windows.SECURITY_INFORMATION(windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	}
	return windows.SetNamedSecurityInfo(native, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
}

// unlock restores inherited permissions on every path this backend locked.
// Called from the explicit `tg-agent unlock` command, never on shutdown: a
// crashed agent must not silently drop the protection.
func (w *WindowsACL) unlock() error {
	roots, err := loadRoots(w.state)
	if err != nil {
		return err
	}
	var errs []string
	for _, native := range roots {
		if _, statErr := os.Stat(native); statErr != nil {
			continue
		}
		err := windows.SetNamedSecurityInfo(native, windows.SE_FILE_OBJECT,
			windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION),
			nil, nil, nil, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", native, err))
			continue
		}
		if w.mic {
			// Back to Medium so the operator's normal tooling can rewrite the
			// tree again after the agent is retired.
			if micErr := setIntegrity(native, levelMedium, true); micErr != nil {
				errs = append(errs, fmt.Sprintf("%s (MIC reset): %v", native, micErr))
			}
		}
	}
	_ = os.Remove(rootsFile(w.state))
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// expiryLoop re-applies the DACL when a grant expires so the temporary write
// ACE disappears even if the agent is not otherwise busy.
func (w *WindowsACL) expiryLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.mu.Lock()
			rt := w.rt
			w.mu.Unlock()
			if rt.Policy == nil || len(rt.Grants) == 0 {
				continue
			}
			now := time.Now().Unix()
			expired := false
			for _, g := range rt.Grants {
				if g.ExpiresAt != 0 && g.ExpiresAt <= now {
					expired = true
				}
			}
			if expired {
				_ = w.Update(rt)
			}
		}
	}
}

func rootsFile(stateDir string) string {
	return filepath.Join(stateDir, "windows-acl-roots.json")
}

func (w *WindowsACL) saveRoots(applied map[string]string) error {
	if w.state == "" {
		return nil
	}
	if err := os.MkdirAll(w.state, 0o750); err != nil {
		return err
	}
	list := make([]string, 0, len(applied))
	for _, native := range applied {
		list = append(list, native)
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rootsFile(w.state), raw, 0o600)
}

func loadRoots(stateDir string) ([]string, error) {
	if stateDir == "" {
		return nil, errors.New("windows-acl: state directory is required")
	}
	raw, err := os.ReadFile(rootsFile(stateDir))
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Unlock restores inherited permissions (explicit operator action).
func Unlock(stateDir string) error {
	w := &WindowsACL{state: stateDir, log: slog.Default()}
	if err := enablePrivilege("SeSecurityPrivilege"); err == nil {
		w.mic = true
	}
	return w.unlock()
}

// Health implements Enforcer.
func (w *WindowsACL) Health() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.health != nil {
		return w.health
	}
	for _, native := range w.applied {
		sd, err := windows.GetNamedSecurityInfo(native, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		if dacl == nil {
			return fmt.Errorf("windows-acl: %s has an empty DACL", native)
		}
		if w.mic {
			level, err := integrityOf(native)
			if err != nil {
				return err
			}
			expected := w.idleLevel
			if w.grantCovers(w.rt, normFromNative(native), time.Now().Unix()) && expected > levelMedium {
				expected = levelMedium
			}
			if level != expected {
				return fmt.Errorf("windows-acl: %s has integrity level %d, expected %d", native, level, expected)
			}
		}
	}
	return nil
}

// Events implements Enforcer.
func (w *WindowsACL) Events() <-chan Event { return w.events.Events() }

// Close stops background work but deliberately leaves the ACLs locked.
func (w *WindowsACL) Close() error {
	w.once.Do(func() {
		close(w.stop)
		w.watchMu.Lock()
		for _, wv := range w.watchers {
			_ = wv.Close()
		}
		w.watchers = nil
		w.watchMu.Unlock()
		w.events.Close()
		if w.base != nil {
			_ = w.base.Close()
		}
	})
	return nil
}

// normalizeRulePath converts a policy path to the slash spelling used by the
// shared model.
func normalizeRulePath(p string) (string, bool) {
	return normalizeOnWindows(p)
}

func nativePath(norm string) string {
	return strings.ReplaceAll(norm, "/", `\`)
}
