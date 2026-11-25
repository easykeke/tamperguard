//go:build linux

package enforcer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/baseline"
	"github.com/easykeke/tamperguard/internal/policy"
	"github.com/easykeke/tamperguard/internal/token"
)

// fanotifyMask is what we ask the kernel to report inside protected trees.
//
// Only file-level events are requested. Directory-entry events (FAN_CREATE,
// FAN_DELETE, FAN_MOVED_FROM, FAN_MOVED_TO) require a FAN_REPORT_FID group and
// open-by-handle path resolution, which depends on filesystem support; creations
// and deletions are therefore recovered by the periodic scan instead.
const fanotifyMask = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE |
	unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD

// Fanotify is the degraded enforcement backend.
//
// Why it cannot block: fanotify permission events do not carry the open flags,
// so a policy cannot tell a read from a write without blocking reads too, which
// would break serving the site. This backend therefore detects and reverts:
//
//   - an unauthorised write to an existing protected file is reverted on close,
//     typically within milliseconds;
//   - deletions and newly created files are recovered by a periodic scan
//     (default 30 s), because the directory-entry events that would report them
//     immediately are not available without FID reporting;
//   - a writer whose uid is configured as a publisher and whose request is
//     covered by a live grant is allowed to change the file, and that content
//     becomes the new baseline.
//
// The capability is reported as degraded, so the control plane requires an
// explicit approval before counting the node as protected.
type Fanotify struct {
	fd            int
	log           *slog.Logger
	base          *baseline.Manager
	self          int
	publisherUIDs []int
	scanInterval  time.Duration

	mu          sync.Mutex
	rt          Runtime
	marks       map[string]bool
	digest      string
	snapshotted bool
	healthErr   error
	lastRestore map[string]time.Time

	events *Buffer
	stop   chan struct{}
	done   chan struct{}
	scan   chan struct{}
	once   sync.Once
}

// NewFanotify opens the fanotify instance and a baseline rooted under stateDir.
func NewFanotify(stateDir string, publisherUIDs []int) (*Fanotify, error) {
	if stateDir == "" {
		return nil, errors.New("fanotify: state directory is required for the baseline")
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK,
		unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify: init (needs CAP_SYS_ADMIN): %w", err)
	}
	base, err := baseline.Open(filepath.Join(stateDir, "baseline"))
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	f := &Fanotify{
		fd:            fd,
		log:           slog.Default(),
		base:          base,
		self:          os.Getpid(),
		publisherUIDs: publisherUIDs,
		scanInterval:  scanInterval(),
		marks:         map[string]bool{},
		lastRestore:   map[string]time.Time{},
		events:        NewBuffer(512),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		scan:          make(chan struct{}, 1),
	}
	go f.readLoop()
	go f.scanLoop()
	return f, nil
}

func scanInterval() time.Duration {
	if v := os.Getenv("TG_FAN_SCAN_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Second
}

// Name implements Enforcer.
func (f *Fanotify) Name() string { return "fanotify" }

// Capability implements Enforcer.
func (f *Fanotify) Capability() Capability {
	return Capability{
		Kind:      "fanotify",
		Available: true,
		Degraded:  true,
		Reason:    "detect-and-restore: writes are reverted after they land; deletions and creations recovered by periodic scan",
	}
}

// Update applies a runtime: marks directories and (re)snapshots the baseline.
func (f *Fanotify) Update(rt Runtime) error {
	f.mu.Lock()
	prevDigest := f.digest
	f.rt = rt
	f.mu.Unlock()

	if rt.Policy == nil {
		return nil
	}
	digest := rt.Policy.Digest
	if digest != prevDigest || !f.snapshotted {
		roots := make([]string, 0, len(rt.Policy.Policy.Paths))
		for _, r := range rt.Policy.Policy.Paths {
			roots = append(roots, r.Path)
		}
		if err := f.base.Snapshot(roots); err != nil {
			f.log.Warn("fanotify: baseline snapshot failed", "err", err)
		}
		f.log.Info("fanotify: baseline snapshot", "paths", f.base.Len())
		f.mu.Lock()
		f.digest = digest
		f.snapshotted = true
		f.mu.Unlock()
	}

	for _, rule := range rt.Policy.Policy.Paths {
		dirs, err := collectDirs(rule.Path)
		if err != nil {
			f.log.Warn("fanotify: cannot enumerate protected tree", "path", rule.Path, "err", err)
			continue
		}
		for _, dir := range dirs {
			f.mu.Lock()
			marked := f.marks[dir]
			f.mu.Unlock()
			if marked {
				continue
			}
			if err := unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD, fanotifyMask, unix.AT_FDCWD, dir); err != nil {
				if errors.Is(err, syscall.ENOSPC) {
					f.log.Error("fanotify: mark limit reached", "dir", dir, "err", err)
				} else {
					f.log.Warn("fanotify: mark failed", "dir", dir, "err", err)
				}
				continue
			}
			f.mu.Lock()
			f.marks[dir] = true
			f.mu.Unlock()
		}
	}
	select {
	case f.scan <- struct{}{}:
	default:
	}
	return nil
}

func collectDirs(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{abs}, nil
	}
	dirs := []string{abs}
	err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == abs {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	return dirs, err
}

func (f *Fanotify) isPublisherUID(uid int) bool {
	for _, u := range f.publisherUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

// grantFor returns the token authorising path right now, if any.
func (f *Fanotify) grantFor(rt Runtime, path string, now int64) (string, bool) {
	valid := rt.ValidGrants("", "", now)
	f.debug("grantFor", "path", path, "grants", len(rt.Grants), "valid", len(valid))
	for _, g := range valid {
		for _, p := range g.Paths {
			if token.PathCovered(p, path) {
				return g.TokenID, true
			}
		}
	}
	return "", false
}

// ---------- event path ----------

func (f *Fanotify) readLoop() {
	defer close(f.done)
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(f.fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				select {
				case <-f.stop:
					return
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}
			select {
			case <-f.stop:
				return
			default:
			}
			f.log.Warn("fanotify: read loop failed", "err", err)
			f.setHealth(err)
			return
		}
		offset := 0
		for offset+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) <= n {
			md := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if md.Event_len == 0 || offset+int(md.Event_len) > n {
				break
			}
			f.handleMetadata(md)
			offset += int(md.Event_len)
		}
	}
}

func (f *Fanotify) handleMetadata(md *unix.FanotifyEventMetadata) {
	path := ""
	if md.Fd >= 0 {
		if p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(md.Fd))); err == nil {
			path = p
		}
		unix.Close(int(md.Fd))
	}
	f.debug("raw event", "mask", fmt.Sprintf("0x%x", md.Mask), "pid", md.Pid, "self", f.self, "path", path)
	if int(md.Pid) == f.self {
		return // our own restore writes
	}
	if md.Mask&unix.FAN_CLOSE_WRITE == 0 {
		return // MODIFY alone is noise: the close is the actionable event
	}
	if path == "" || path[0] != '/' {
		f.debug("event without path", "mask", fmt.Sprintf("0x%x", md.Mask))
		return
	}
	f.handleCloseWrite(path, int(md.Pid))
}

func (f *Fanotify) handleCloseWrite(path string, pid int) {
	f.mu.Lock()
	rt := f.rt
	f.mu.Unlock()

	now := time.Now().Unix()
	subj := resolveSubject(pid)
	req := policy.Request{Path: path, Op: policy.OpOpenWrite, Subject: subj, Now: now}
	d := rt.Decide(req)

	if d.Allow && d.Mode == policy.ModeObserve && d.Reason == policy.ReasonObserve {
		f.emit(Event{Time: now, Kind: audit.KindWriteObserved, Path: path, Op: req.Op, Subject: subj, Reason: d.Reason})
		return
	}

	granted := false
	tokenID := ""
	if !d.Allow && f.isPublisherUID(subj.UID) {
		tokenID, granted = f.grantFor(rt, path, now)
	}
	f.debug("close_write", "path", path, "uid", subj.UID, "allow", d.Allow, "granted", granted, "reason", d.Reason)
	if d.Allow || granted {
		f.base.Take(path)
		f.debug("take", "path", path, "granted", granted)
		f.emit(Event{Time: now, Kind: audit.KindWriteAllowed, Path: path, Op: req.Op, Subject: subj, TokenID: tokenID, Reason: d.Reason})
		return
	}

	if f.recentlyRestored(path) {
		return
	}
	if err := f.base.RestoreTree(path); err != nil {
		f.log.Error("fanotify: restore failed", "path", path, "err", err)
	}
	kind := audit.KindWriteBlocked
	if d.Mode == policy.ModeObserve {
		kind = audit.KindWriteObserved
	}
	f.emit(Event{Time: now, Kind: kind, Path: path, Op: req.Op, Subject: subj, Reason: d.Reason})
}

// recentlyRestored debounces restores for one path (an attacker writing in a
// loop must not turn into an unbounded stream of restores and audit records).
func (f *Fanotify) recentlyRestored(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.lastRestore[path]; ok && time.Since(t) < 500*time.Millisecond {
		return true
	}
	f.lastRestore[path] = time.Now()
	if len(f.lastRestore) > 4096 {
		f.lastRestore = map[string]time.Time{path: time.Now()}
	}
	return false
}

// ---------- scan path ----------

// scanLoop periodically reconciles the protected tree with the baseline. It is
// what recovers deletions and newly created files, which the event mask cannot
// report on this class of fanotify group.
func (f *Fanotify) scanLoop() {
	t := time.NewTicker(f.scanInterval)
	defer t.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-t.C:
		case <-f.scan:
		}
		f.scanOnce()
	}
}

func (f *Fanotify) scanOnce() {
	f.mu.Lock()
	rt := f.rt
	f.mu.Unlock()
	if rt.Policy == nil {
		return
	}
	now := time.Now().Unix()

	grantActive := func(path string) bool {
		_, ok := f.grantFor(rt, path, now)
		return ok
	}

	// 1. Missing or modified baseline entries.
	for _, e := range f.base.List() {
		if grantActive(e.Path) {
			continue
		}
		if e.IsDir {
			if _, err := os.Lstat(e.Path); err != nil {
				_ = os.MkdirAll(e.Path, os.FileMode(e.Mode))
			}
			continue
		}
		data, err := os.ReadFile(e.Path)
		changed := err != nil
		if !changed {
			sum := sha256.Sum256(data)
			changed = hex.EncodeToString(sum[:]) != e.SHA256
		}
		if !changed {
			continue
		}
		if f.recentlyRestored(e.Path) {
			continue
		}
		f.debug("scan-restore", "path", e.Path, "baseline", e.SHA256[:8])
		if err := f.base.RestoreTree(e.Path); err != nil {
			f.log.Error("fanotify: scan restore failed", "path", e.Path, "err", err)
			continue
		}
		f.emit(Event{
			Time: now, Kind: audit.KindWriteBlocked, Path: e.Path,
			Op:      policy.OpOpenWrite,
			Subject: policy.Subject{ExePath: "scan"},
			Reason:  "scan-mismatch",
		})
	}

	// 2. Files that appeared after the snapshot.
	for _, rule := range rt.Policy.Policy.Paths {
		root, err := filepath.Abs(rule.Path)
		if err != nil {
			continue
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			// Ignore our own in-flight temporary files.
			if strings.HasPrefix(filepath.Base(p), ".tg-") {
				return nil
			}
			if _, ok := f.base.Get(p); ok {
				return nil
			}
			if grantActive(p) {
				return nil
			}
			if err := os.Remove(p); err != nil {
				return nil
			}
			f.emit(Event{
				Time: now, Kind: audit.KindWriteBlocked, Path: p,
				Op:      policy.OpCreate,
				Subject: policy.Subject{ExePath: "scan"},
				Reason:  "scan-untracked",
			})
			return nil
		})
	}
}

func resolveSubject(pid int) policy.Subject {
	subj := policy.Subject{PID: pid}
	if pid <= 0 {
		return subj
	}
	proc := "/proc/" + strconv.Itoa(pid)
	var st unix.Stat_t
	if err := unix.Stat(proc, &st); err == nil {
		subj.UID = int(st.Uid)
	}
	if exe, err := os.Readlink(proc + "/exe"); err == nil {
		subj.ExePath = exe
	}
	return subj
}

func (f *Fanotify) emit(ev Event) {
	f.events.Emit(ev)
}

func (f *Fanotify) debug(msg string, args ...any) {
	if os.Getenv("TG_FAN_DEBUG") == "" {
		return
	}
	f.log.Info("fanotify: "+msg, args...)
}

func (f *Fanotify) setHealth(err error) {
	f.mu.Lock()
	f.healthErr = err
	f.mu.Unlock()
}

// Events implements Enforcer.
func (f *Fanotify) Events() <-chan Event { return f.events.Events() }

// Health implements Enforcer.
func (f *Fanotify) Health() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.healthErr != nil {
		return f.healthErr
	}
	select {
	case <-f.done:
		return errors.New("fanotify: event loop stopped")
	default:
	}
	if len(f.marks) == 0 && f.rt.Policy != nil {
		return errors.New("fanotify: no marks installed")
	}
	return nil
}

// Close implements Enforcer.
func (f *Fanotify) Close() error {
	var err error
	f.once.Do(func() {
		close(f.stop)
		_ = unix.Close(f.fd)
		<-f.done
		if cerr := f.base.Close(); cerr != nil {
			err = cerr
		}
		f.events.Close()
	})
	return err
}
