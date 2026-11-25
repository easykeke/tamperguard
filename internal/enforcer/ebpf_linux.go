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
	opFileWrite      = 1
	opFileOpen       = 2
	opInodePerm      = 3
	opCreate         = 4
	opMkdir          = 5
	opUnlink         = 6
	opRmdir          = 7
	opRename         = 8
	opLink           = 9
	opSetattr        = 10
	opSetxattr       = 11
	opMmap           = 12
	opMprotect       = 13
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
	objs   tgObjects
	links  []link.Link
	reader *ringbuf.Reader
	events *Buffer
	log    *slog.Logger

	// publisherUIDs are the uids that may use a live grant. A token authorises
	// a publisher identity; the kernel can only see uids, so the mapping is
	// configured explicitly rather than inferred.
	publisherUIDs []int

	mu        sync.Mutex
	dirs      map[tgInodeKey]string
	files     map[tgInodeKey]string
	grantKeys map[tgGrantKey]uint64
	healthErr error

	closeOnce sync.Once
	closed    chan struct{}
}

// NewEBPF loads the CO-RE object, attaches every LSM hook and starts the event
// reader. Any failure closes what was already loaded, so a partially attached
// control never looks healthy.
func NewEBPF(publisherUIDs []int) (*EBPF, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		// Not fatal on kernels with memcg accounting, but worth knowing.
		slog.Default().Debug("enforcer: could not raise memlock limit", "err", err)
	}
	objs := tgObjects{}
	if err := loadTgObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load object: %w", err)
	}
	e := &EBPF{
		objs:          objs,
		events:        NewBuffer(1024),
		log:           slog.Default(),
		publisherUIDs: publisherUIDs,
		dirs:          map[tgInodeKey]string{},
		files:         map[tgInodeKey]string{},
		grantKeys:     map[tgGrantKey]uint64{},
		closed:        make(chan struct{}),
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
	}
	if err := objs.TgConfig.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		e.Close()
		return nil, fmt.Errorf("ebpf: enable enforcement: %w", err)
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

// Update rebuilds the protected sets and grant table from the runtime state.
//
// Protection changes are applied as a diff: new entries are added before stale
// entries are removed, so the map is never empty in between (fail-closed during
// the update).
func (e *EBPF) Update(rt Runtime) error {
	newDirs := map[tgInodeKey]string{}
	newFiles := map[tgInodeKey]string{}
	var errs []string

	if rt.Policy != nil {
		for _, rule := range rt.Policy.Policy.Paths {
			if rule.Mode != policy.ModeEnforce {
				// Observe-mode rules are recorded by policy.Decide in the
				// simulation backend; the kernel path currently only enforces.
				continue
			}
			dirs, files, err := collectInodes(rule.Path, rule.Recursive)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			for k, v := range dirs {
				newDirs[k] = v
			}
			for k, v := range files {
				newFiles[k] = v
			}
		}
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

	// Additions first (fail-closed window), then removals.
	for k := range newDirs {
		if _, ok := e.dirs[k]; !ok {
			if err := e.objs.ProtectedDirs.Update(k, uint8(1), ebpf.UpdateAny); err != nil {
				errs = append(errs, "dir "+k.String()+": "+err.Error())
			}
		}
	}
	for k := range newFiles {
		if _, ok := e.files[k]; !ok {
			if err := e.objs.ProtectedFiles.Update(k, uint8(1), ebpf.UpdateAny); err != nil {
				errs = append(errs, "file "+k.String()+": "+err.Error())
			}
		}
	}
	for k := range e.dirs {
		if _, ok := newDirs[k]; !ok {
			_ = e.objs.ProtectedDirs.Delete(k)
		}
	}
	for k := range e.files {
		if _, ok := newFiles[k]; !ok {
			_ = e.objs.ProtectedFiles.Delete(k)
		}
	}
	e.dirs = newDirs
	e.files = newFiles

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
	path := e.files[tgInodeKey{Ino: ev.Ino, Dev: ev.Dev}]
	if path == "" {
		path = e.dirs[tgInodeKey{Ino: ev.Ino, Dev: ev.Dev}]
	}
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
