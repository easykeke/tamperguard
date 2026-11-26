//go:build linux

package enforcer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/easykeke/tamperguard/internal/audit"
	"github.com/easykeke/tamperguard/internal/policy"
)

// ebpfEvent mirrors struct event in bpf/tg_protect.bpf.c. The layout is part
// of the ABI between kernel and userspace; do not reorder fields.
type ebpfEvent struct {
	Op      uint32
	Verdict uint32
	UID     uint32
	PID     uint32
	Ino     uint64
	Dev     uint32
	Pad     uint32
	Ret     int64
	Comm    [16]byte
}

const (
	verdictAllow     = 0
	verdictDeny      = 1
	verdictWouldDeny = 2

	// Map value semantics for protected_dirs / protected_files.
	modeEnforce uint8 = 1
	modeObserve uint8 = 2

	opFileWrite = 1
	opFileOpen  = 2
	opInodePerm = 3
	opCreate    = 4
	opMkdir     = 5
	opUnlink    = 6
	opRmdir     = 7
	opRename    = 8
	opLink      = 9
	opSetattr   = 10
	opSetxattr  = 11
	opMmap      = 12
	opMprotect  = 13
)

var opNames = map[uint32]policy.Op{
	opFileWrite: "open_write",
	opFileOpen:  "open_write",
	opInodePerm: "open_write",
	opCreate:    "create",
	opMkdir:     "create",
	opUnlink:    "unlink",
	opRmdir:     "unlink",
	opRename:    "rename",
	opLink:      "link",
	opSetattr:   "setattr",
	opSetxattr:  "setattr",
	opMmap:      "mmap_write",
	opMprotect:  "mmap_write",
}

// EBPF is the kernel-backed enforcer. It owns the loaded programs and the
// inode/grant maps, and turns ring buffer records into audit events.
type EBPF struct {
	objs      tgObjects
	links     []link.Link
	pinned    []string
	selfPaths []string
	reader    *ringbuf.Reader
	events    *Buffer
	log       *slog.Logger

	// publisherUIDs are the uids that may use a live grant. A token authorises
	// a publisher identity; the kernel can only see uids, so the mapping is
	// configured explicitly rather than inferred.
	publisherUIDs []int

	mu        sync.Mutex
	dirs      map[tgInodeKey]uint8
	files     map[tgInodeKey]uint8
	paths     map[tgInodeKey]string
	grantKeys map[tgGrantKey]uint64
	healthErr error

	closeOnce sync.Once
	closed    chan struct{}
}

// NewEBPF loads the CO-RE object, attaches every LSM hook and starts the event
// reader. Any failure closes what was already loaded, so a partially attached
// control never looks healthy.
func NewEBPF(publisherUIDs []int) (*EBPF, error) {
	if !bpfLSMActive() {
		return nil, errors.New("ebpf: bpf LSM is not active (kernel command line needs lsm=...,bpf)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		// Not fatal on kernels with memcg accounting, but worth knowing.
		slog.Default().Debug("enforcer: could not raise memlock limit", "err", err)
	}
	// Links pinned by a previous run keep enforcement alive after SIGKILL.
	// Remove them before attaching so the new programs use the current maps.
	if pinningEnabled() {
		if stale, err := DetachPinned(); err != nil {
			slog.Default().Warn("enforcer: could not clear stale pinned links", "err", err)
		} else if stale > 0 {
			slog.Default().Info("enforcer: cleared stale pinned LSM links", "count", stale)
		}
	}
	objs := tgObjects{}
	if err := loadTgObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load object: %w", err)
	}
	if pinningEnabled() {
		if err := pinConfigMap(objs.TgConfig); err != nil {
			slog.Default().Warn("enforcer: config map not pinned; maintenance detach cannot disable it",
				"err", err)
		}
	}
	e := &EBPF{
		objs:          objs,
		events:        NewBuffer(1024),
		log:           slog.Default(),
		publisherUIDs: publisherUIDs,
		dirs:          map[tgInodeKey]uint8{},
		files:         map[tgInodeKey]uint8{},
		paths:         map[tgInodeKey]string{},
		grantKeys:     map[tgGrantKey]uint64{},
		closed:        make(chan struct{}),
	}
	// The agent process itself is the only writer allowed on its own files.
	if err := objs.TgSelfPids.Update(uint32(os.Getpid()), uint8(1), ebpf.UpdateAny); err != nil {
		slog.Default().Warn("enforcer: self-protection pid not registered", "err", err)
	}
	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"file_permission", objs.TgFilePermission},
		{"file_open", objs.TgFileOpen},
		{"inode_permission", objs.TgInodePermission},
		{"inode_create", objs.TgInodeCreate},
		{"inode_mkdir", objs.TgInodeMkdir},
		{"inode_unlink", objs.TgInodeUnlink},
		{"inode_rmdir", objs.TgInodeRmdir},
		{"inode_rename", objs.TgInodeRename},
		{"inode_link", objs.TgInodeLink},
		{"inode_setattr", objs.TgInodeSetattr},
		{"inode_setxattr", objs.TgInodeSetxattr},
		{"mmap_file", objs.TgMmapFile},
		{"file_mprotect", objs.TgFileMprotect},
		{"d_instantiate", objs.TgD_instantiate},
	}
	for _, p := range progs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			for _, done := range e.links {
				_ = done.Close()
			}
			_ = objs.Close()
			return nil, fmt.Errorf("ebpf: attach %s: %w", p.name, err)
		}
		e.links = append(e.links, l)
		if pinningEnabled() {
			if path, err := pinLink(p.name, l); err != nil {
				slog.Default().Warn("enforcer: link not pinned; protection ends if the agent is killed",
					"hook", p.name, "err", err)
			} else {
				e.pinned = append(e.pinned, path)
			}
		}
	}
	if err := objs.TgConfig.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		e.Close()
		return nil, fmt.Errorf("ebpf: enable enforcement: %w", err)
	}
	// Publisher uids drive in-kernel grant inheritance for newly created
	// inodes; without them a nested directory created during a release would
	// be protected but not yet granted.
	if err := e.writePublisherUIDs(publisherUIDs); err != nil {
		e.Close()
		return nil, err
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}
	e.reader = rd
	go e.readLoop()
	e.log.Info("eBPF LSM enforcement active", "hooks", len(e.links))
	return e, nil
}

// Name implements Enforcer.
func (e *EBPF) Name() string { return "ebpf-lsm" }

// Capability implements Enforcer.
func (e *EBPF) Capability() Capability {
	return Capability{Kind: "ebpf-lsm", Available: true, Degraded: false, Reason: "kernel LSM hooks attached"}
}

// SetSelfPaths protects the agent's own files. The agent's pid is inserted in the
// kernel self-pid map, so the agent keeps working while any other process —
// including root — is denied writes to these paths.
func (e *EBPF) SetSelfPaths(paths []string) error {
	e.selfPaths = append([]string(nil), paths...)
	for _, p := range paths {
		_, files, err := collectInodes(p, false)
		if err != nil {
			return err
		}
		for k := range files {
			if err := e.objs.ProtectedFiles.Update(k, uint8(modeEnforce), ebpf.UpdateAny); err != nil {
				return err
			}
		}
	}
	return nil
}

// Update rebuilds the protected sets and grant table from the runtime state.
//
// Protection changes are applied as a diff: new entries are added before stale
// entries are removed, so the map is never empty in between (fail-closed during
// the update). Rules carry their mode into the map value, so observe rules
// produce audit events without blocking.
func (e *EBPF) Update(rt Runtime) error {
	desiredDirs := map[tgInodeKey]uint8{}
	desiredFiles := map[tgInodeKey]uint8{}
	desiredPaths := map[tgInodeKey]string{}
	var errs []string

	// merge applies one rule's inode set. enforce wins over observe when two
	// rules cover the same inode, so tightening never depends on rule order.
	merge := func(dst map[tgInodeKey]uint8, src map[tgInodeKey]string, mode uint8) {
		for k, p := range src {
			if cur, ok := dst[k]; ok && cur == modeEnforce {
				continue
			}
			dst[k] = mode
			desiredPaths[k] = p
		}
	}

	if rt.Policy != nil {
		for _, rule := range rt.Policy.Policy.Paths {
			mode := modeEnforce
			if rule.Mode == policy.ModeObserve {
				mode = modeObserve
			}
			dirs, files, err := collectInodes(rule.Path, rule.Recursive)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			merge(desiredDirs, dirs, mode)
			merge(desiredFiles, files, mode)
		}
	}

	// Self-protection paths are merged on every update so a policy sync cannot
	// silently drop the agent's own files from the protected set.
	for _, p := range e.selfPaths {
		dirs, files, err := collectInodes(p, false)
		if err != nil {
			continue
		}
		merge(desiredDirs, dirs, modeEnforce)
		merge(desiredFiles, files, modeEnforce)
	}

	grantNow := bootTimeNs()
	newGrants := map[tgGrantKey]uint64{}
	if rt.Policy != nil {
		for _, g := range rt.Grants {
			if g.ExpiresAt <= time.Now().Unix() {
				continue
			}
			if rt.Revocations.Has("token", g.TokenID) || rt.Revocations.Has("subject", g.Subject) {
				continue
			}
			ttl := time.Until(time.Unix(g.ExpiresAt, 0))
			if ttl <= 0 {
				continue
			}
			expiry := grantNow + uint64(ttl.Nanoseconds())
			for _, p := range g.Paths {
				dirs, files, err := collectInodes(p, true)
				if err != nil {
					continue
				}
				for k := range dirs {
					for _, uid := range e.publisherUIDs {
						newGrants[tgGrantKey{Uid: uint32(uid), Dev: k.Dev, Ino: k.Ino}] = expiry
					}
				}
				for k := range files {
					for _, uid := range e.publisherUIDs {
						newGrants[tgGrantKey{Uid: uint32(uid), Dev: k.Dev, Ino: k.Ino}] = expiry
					}
				}
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Additions/updates first (fail-closed window), then removals.
	apply := func(name string, m *ebpf.Map, have, want map[tgInodeKey]uint8) {
		for k, v := range want {
			if cur, ok := have[k]; ok && cur == v {
				continue
			}
			if err := m.Update(k, v, ebpf.UpdateAny); err != nil {
				errs = append(errs, name+" "+k.String()+": "+err.Error())
			}
		}
		for k := range have {
			if _, ok := want[k]; !ok {
				_ = m.Delete(k)
			}
		}
	}
	apply("dir", e.objs.ProtectedDirs, e.dirs, desiredDirs)
	apply("file", e.objs.ProtectedFiles, e.files, desiredFiles)
	e.dirs = desiredDirs
	e.files = desiredFiles
	e.paths = desiredPaths

	for k, expiry := range newGrants {
		if err := e.objs.Grants.Update(k, expiry, ebpf.UpdateAny); err != nil {
			errs = append(errs, "grant: "+err.Error())
		}
	}
	for k := range e.grantKeys {
		if _, ok := newGrants[k]; !ok {
			_ = e.objs.Grants.Delete(k)
		}
	}
	e.reconcileGrants(newGrants)
	e.grantKeys = newGrants

	if len(errs) > 0 {
		e.log.Warn("ebpf map update had errors", "errors", strings.Join(errs, "; "))
	}
	return nil
}

// Counters returns the kernel-side diagnostic counters (see tg_stats in the
// BPF program): [0] file_permission calls, [1] protected lookups that hit,
// [2] denials, [3] file_open calls, [4] inode_permission calls,
// [5] inode_create calls.
func (e *EBPF) Counters() [8]uint64 {
	var out [8]uint64
	for i := uint32(0); i < 8; i++ {
		var v uint64
		if err := e.objs.TgStats.Lookup(i, &v); err == nil {
			out[i] = v
		}
	}
	return out
}

// reconcileGrants removes grant entries that userspace did not install.
//
// The kernel adds inherited grants for inodes created inside a granted tree
// (d_instantiate), and userspace cannot track those keys. Without a sweep, a
// revocation would leave inherited grants alive until the token TTL, which is a
// real bypass. The sweep runs on every sync and only deletes entries absent
// from the authoritative set, so the worst case is a short race during a
// release, where a just-created file briefly loses its grant and the publisher's
// retry loop covers it.
func (e *EBPF) reconcileGrants(desired map[tgGrantKey]uint64) {
	it := e.objs.Grants.Iterate()
	var key tgGrantKey
	var val uint64
	for it.Next(&key, &val) {
		if _, ok := desired[key]; !ok {
			_ = e.objs.Grants.Delete(key)
		}
	}
}

// SetPublisherUIDs updates the uids allowed to consume grants. It is called
// whenever the policy changes, so that process writer rules (which carry a uid)
// take effect without restarting the agent.
func (e *EBPF) SetPublisherUIDs(uids []int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.publisherUIDs = uids
	return e.writePublisherUIDsLocked(uids)
}

// writePublisherUIDs writes the kernel map; callers hold no lock or are in
// construction.
func (e *EBPF) writePublisherUIDs(uids []int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.writePublisherUIDsLocked(uids)
}

func (e *EBPF) writePublisherUIDsLocked(uids []int) error {
	var cfg tgPubCfg
	cfg.Count = uint32(len(uids))
	for i, uid := range uids {
		if i >= len(cfg.Uids) {
			e.log.Warn("ebpf: more publisher uids than the kernel map holds; extra uids ignored",
				"configured", len(uids), "capacity", len(cfg.Uids))
			break
		}
		cfg.Uids[i] = uint32(uid)
	}
	if err := e.objs.Publishers.Update(uint32(0), cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ebpf: set publisher uids: %w", err)
	}
	return nil
}

// Stats returns the number of entries currently installed in the kernel maps.
// Used by diagnostics and by the integration test.
func (e *EBPF) Stats() (dirs, files, grants int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.dirs), len(e.files), len(e.grantKeys)
}

func (k tgInodeKey) String() string {
	return fmt.Sprintf("dev=%d ino=%d", k.Dev, k.Ino)
}

// collectInodes walks path and returns the inode sets used by the kernel map.
func collectInodes(path string, recursive bool) (map[tgInodeKey]string, map[tgInodeKey]string, error) {
	dirs := map[tgInodeKey]string{}
	files := map[tgInodeKey]string{}
	abs, err := filepath.Abs(path)
	if err != nil {
		return dirs, files, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return dirs, files, fmt.Errorf("enforcer: stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		if k, ok := keyOf(abs, info); ok {
			files[k] = abs
		}
		return dirs, files, nil
	}
	if k, ok := keyOf(abs, info); ok {
		dirs[k] = abs
	}
	if !recursive {
		return dirs, files, nil
	}
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: keep going, report nothing
		}
		if !d.IsDir() {
			return nil
		}
		if p == abs {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if k, ok := keyOf(p, fi); ok {
			dirs[k] = p
		}
		return nil
	})
	return dirs, files, err
}

func keyOf(p string, fi fs.FileInfo) (tgInodeKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return tgInodeKey{}, false
	}
	// struct stat reports st_dev in the glibc/userspace encoding, while the
	// kernel compares inode->i_sb->s_dev, which is MKDEV(major, minor) =
	// (major << 20) | minor. Feeding the stat form to the map makes every
	// lookup miss on filesystems with a non-zero major device number (the
	// mismatch is invisible on tmpfs, where both encodings coincide).
	// Note: unix.Mkdev produces the userspace encoding again, not MKDEV.
	u32dev := uint32(st.Dev)
	major := (u32dev >> 8) & 0xfff
	minor := (u32dev & 0xff) | ((u32dev >> 12) & 0xfff00)
	kdev := (major << 20) | minor
	return tgInodeKey{Ino: st.Ino, Dev: kdev}, true
}

// bootTimeNs approximates bpf_ktime_get_ns() using /proc/uptime.
func bootTimeNs() uint64 {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(sec * 1e9)
}

func (e *EBPF) readLoop() {
	for {
		rec, err := e.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			e.setHealth(err)
			continue
		}
		var ev ebpfEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		e.handle(ev)
	}
}

func (e *EBPF) handle(ev ebpfEvent) {
	kind := audit.KindWriteBlocked
	switch ev.Verdict {
	case verdictAllow:
		kind = audit.KindWriteAllowed
	case verdictWouldDeny:
		kind = audit.KindWriteObserved
	}
	op, ok := opNames[ev.Op]
	if !ok {
		op = "write"
	}
	e.mu.Lock()
	path := e.paths[tgInodeKey{Ino: ev.Ino, Dev: ev.Dev}]
	e.mu.Unlock()
	comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
	reason := "kernel-lsm"
	if path == "" {
		path = fmt.Sprintf("inode:%d", ev.Ino)
	}
	e.events.Emit(Event{
		Time: time.Now().Unix(),
		Kind: kind,
		Path: path,
		Op:   op,
		Subject: policy.Subject{
			PID:     int(ev.PID),
			UID:     int(ev.UID),
			ExePath: "comm:" + comm,
		},
		Reason: reason,
	})
}

func (e *EBPF) setHealth(err error) {
	e.mu.Lock()
	e.healthErr = err
	e.mu.Unlock()
}

// Events implements Enforcer.
func (e *EBPF) Events() <-chan Event { return e.events.Events() }

// Health reports whether the kernel side is still in place. A silently
// detached LSM program is the worst failure mode, so link liveness is checked
// on every heartbeat rather than assumed.
func (e *EBPF) Health() error {
	e.mu.Lock()
	err := e.healthErr
	e.mu.Unlock()
	if err != nil {
		return err
	}
	if len(e.links) == 0 {
		return errors.New("enforcer: no LSM links attached")
	}
	var enforced uint32
	if err := e.objs.TgConfig.Lookup(uint32(0), &enforced); err != nil {
		return fmt.Errorf("enforcer: config map unreadable: %w", err)
	}
	for i, l := range e.links {
		if _, err := l.Info(); err != nil {
			if errors.Is(err, link.ErrNotSupported) {
				continue
			}
			return fmt.Errorf("enforcer: link %d not alive: %w", i, err)
		}
	}
	return nil
}

// Close implements Enforcer.
func (e *EBPF) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.closed)
		if e.reader != nil {
			err = e.reader.Close()
		}
		// Closing a pinned link does not detach it: a stopped agent must not
		// silently remove protection. `tg-agent ebpf-detach` (and uninstall)
		// clears the pins explicitly.
		for _, l := range e.links {
			if cerr := l.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}
		if cerr := e.objs.Close(); cerr != nil && err == nil {
			err = cerr
		}
		e.events.Close()
	})
	return err
}
