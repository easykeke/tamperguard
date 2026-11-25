// SPDX-License-Identifier: Apache-2.0
//
// TamperGuard eBPF LSM enforcement program.
//
// Model
// -----
// "Protected" is expressed as a set of inodes:
//
//   protected_dirs  - every directory of a protected subtree
//   protected_files - explicitly protected files (non-recursive rules)
//
// An inode is protected if it is in protected_files, or if its parent
// directory is in protected_dirs. Checking the parent directory, not just the
// file's own inode, is what makes files created later inside a protected tree
// protected as well.
//
// Authorization is a time-bound grant keyed by (uid, inode). A grant on a
// directory authorizes mutations inside it, which is how the release agent is
// allowed to create new files while a token is live. Grants are installed by
// userspace only after the release token's signature, node binding, path
// scope and manifest digest have all been checked.
//
// Verdicts:
//   0                  allow
//   -EPERM             deny (the write never reaches the filesystem)
//
// Observe-mode rules and a global "not enforcing" switch produce an audit
// event without blocking, so operators can dry-run a rule.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAY_WRITE 0x2
#define MAY_EXEC 0x1

#define O_WRONLY 0x1
#define O_RDWR 0x2
#define O_CREAT 0x40
#define O_TRUNC 0x200

#define PROT_WRITE 0x2

#define MODE_ENFORCE 1
#define MODE_OBSERVE 2

enum tg_op {
	TG_OP_FILE_WRITE = 1,
	TG_OP_FILE_OPEN = 2,
	TG_OP_INODE_PERM = 3,
	TG_OP_CREATE = 4,
	TG_OP_MKDIR = 5,
	TG_OP_UNLINK = 6,
	TG_OP_RMDIR = 7,
	TG_OP_RENAME = 8,
	TG_OP_LINK = 9,
	TG_OP_SETATTR = 10,
	TG_OP_SETXATTR = 11,
	TG_OP_MMAP = 12,
	TG_OP_MPROTECT = 13,
};

enum tg_verdict {
	V_ALLOW = 0,
	V_DENY = 1,
	V_WOULD_DENY = 2,
};

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

struct grant_key {
	__u32 uid;
	__u32 dev;
	__u64 ino;
};

struct event {
	__u32 op;
	__u32 verdict;
	__u32 uid;
	__u32 pid;
	__u64 ino;
	__u32 dev;
	__u32 pad;
	__s64 ret;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct inode_key);
	__type(value, __u8);
} protected_dirs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct inode_key);
	__type(value, __u8);
} protected_files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct grant_key);
	__type(value, __u64); /* expiry in ns since boot */
} grants SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32); /* 1 = enforce, 0 = observe only */
} tg_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * Publisher uids, used to inherit an active grant onto inodes created inside a
 * granted directory. A bounded array keeps the inheritance loop verifier-safe.
 */
struct pub_cfg {
	__u32 count;
	__u32 uids[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pub_cfg);
} publishers SEC(".maps");

/* Debug counters: proves whether hooks run and whether lookups hit. Kept as a
 * permanent diagnostic (cheap, 8 slots) so "protection silently stopped" can be
 * distinguished from "protection works but nothing was attempted". */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} tg_stats SEC(".maps");

/* Diagnostic: inode keys observed on the write-permission path. Retained for
 * field diagnosis (enable by calling see() from a hook); not on the hot path. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inode_key);
	__type(value, __u64);
} tg_seen SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u32 k = idx;
	__u64 *v = bpf_map_lookup_elem(&tg_stats, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int enforcing(void)
{
	__u32 zero = 0;
	__u32 *v = bpf_map_lookup_elem(&tg_config, &zero);
	return v && *v == 1;
}

static __always_inline __u32 inode_dev(struct inode *inode)
{
	return BPF_CORE_READ(inode, i_sb, s_dev);
}

static __always_inline void see(struct inode *inode)
{
	struct inode_key k = {};
	__u64 one = 1;
	__u64 *v;

	if (!inode)
		return;
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = inode_dev(inode);
	v = bpf_map_lookup_elem(&tg_seen, &k);
	if (v) {
		__sync_fetch_and_add(v, 1);
	} else {
		bpf_map_update_elem(&tg_seen, &k, &one, BPF_ANY);
	}
}

static __always_inline __u8 inode_mode(void *map, struct inode *inode)
{
	struct inode_key k = {};
	if (!inode)
		return 0;
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = inode_dev(inode);
	__u8 *v = bpf_map_lookup_elem(map, &k);
	return v ? *v : 0;
}

static __always_inline int inode_granted(struct inode *inode)
{
	struct grant_key k = {};
	__u64 *exp;

	if (!inode)
		return 0;
	k.uid = (__u32)bpf_get_current_uid_gid();
	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = inode_dev(inode);
	exp = bpf_map_lookup_elem(&grants, &k);
	if (!exp)
		return 0;
	return *exp > bpf_ktime_get_ns();
}

static __always_inline void emit(struct inode *inode, __u32 op, __u32 verdict, __s64 ret)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->op = op;
	e->verdict = verdict;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	e->ret = ret;
	if (inode) {
		e->ino = BPF_CORE_READ(inode, i_ino);
		e->dev = inode_dev(inode);
	}
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/*
 * decide() is the single verdict function for inode-scoped hooks.
 * parent may be NULL when only the inode itself is known.
 */
static __always_inline int decide(struct inode *inode, struct inode *parent, __u32 op)
{
	__u8 mode = 0;

	if (inode)
		mode = inode_mode(&protected_files, inode);
	if (!mode && parent)
		mode = inode_mode(&protected_dirs, parent);
	if (!mode)
		return 0;
	bump(1);

	if (inode_granted(inode) || inode_granted(parent)) {
		emit(inode ? inode : parent, op, V_ALLOW, 0);
		return 0;
	}
	if (mode == MODE_OBSERVE || !enforcing()) {
		emit(inode ? inode : parent, op, V_WOULD_DENY, 0);
		return 0;
	}
	bump(2);
	emit(inode ? inode : parent, op, V_DENY, -1);
	return -1;
}

/* decide_dir() gates operations on a directory (create/unlink/rename source). */
static __always_inline int decide_dir(struct inode *dir, __u32 op)
{
	__u8 mode;

	if (!dir)
		return 0;
	mode = inode_mode(&protected_dirs, dir);
	if (!mode)
		return 0;
	if (inode_granted(dir)) {
		emit(dir, op, V_ALLOW, 0);
		return 0;
	}
	if (mode == MODE_OBSERVE || !enforcing()) {
		emit(dir, op, V_WOULD_DENY, 0);
		return 0;
	}
	emit(dir, op, V_DENY, -1);
	return -1;
}

/*
 * inherit_grant copies the parent directory's live grant onto a newly created
 * inode, for every configured publisher uid. Without this, a release that
 * creates a nested directory would write into it before userspace refreshes the
 * index, and the kernel would (correctly but unhelpfully) deny its own release.
 */
static __always_inline void inherit_grant(struct inode *parent, struct inode *child)
{
	__u32 zero = 0;
	struct pub_cfg *cfg;
	__u64 now;
	__u64 pino;
	__u32 pdev;
	__u32 cino;
	__u32 cdev;

	if (!parent || !child)
		return;
	cfg = bpf_map_lookup_elem(&publishers, &zero);
	if (!cfg || cfg->count == 0)
		return;
	now = bpf_ktime_get_ns();
	pino = BPF_CORE_READ(parent, i_ino);
	pdev = inode_dev(parent);
	cino = (__u32)BPF_CORE_READ(child, i_ino);
	cdev = inode_dev(child);

#pragma unroll
	for (int i = 0; i < 8; i++) {
		struct grant_key pk = {};
		struct grant_key ck = {};
		__u64 *exp;

		if ((__u32)i >= cfg->count)
			break;
		pk.uid = cfg->uids[i];
		pk.dev = pdev;
		pk.ino = pino;
		exp = bpf_map_lookup_elem(&grants, &pk);
		if (!exp || *exp <= now)
			continue;
		ck.uid = cfg->uids[i];
		ck.dev = cdev;
		ck.ino = cino;
		bpf_map_update_elem(&grants, &ck, exp, BPF_ANY);
	}
}

static __always_inline struct inode *dentry_inode(struct dentry *de)
{
	if (!de)
		return NULL;
	return BPF_CORE_READ(de, d_inode);
}

static __always_inline struct inode *dentry_parent(struct dentry *de)
{
	if (!de)
		return NULL;
	return BPF_CORE_READ(de, d_parent, d_inode);
}

/* Every write() syscall passes here, including on already-open fds. */
SEC("lsm/file_permission")
int BPF_PROG(tg_file_permission, struct file *file, int mask)
{
	struct dentry *de;
	struct inode *inode;

	bump(0);
	if (!(mask & MAY_WRITE))
		return 0;
	de = BPF_CORE_READ(file, f_path.dentry);
	inode = dentry_inode(de);
	return decide(inode, dentry_parent(de), TG_OP_FILE_WRITE);
}

/* Catches write intent at open time, before any data is written. */
SEC("lsm/file_open")
int BPF_PROG(tg_file_open, struct file *file)
{
	struct dentry *de;
	unsigned int flags;

	flags = BPF_CORE_READ(file, f_flags);
	if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
		return 0;
	de = BPF_CORE_READ(file, f_path.dentry);
	return decide(dentry_inode(de), dentry_parent(de), TG_OP_FILE_OPEN);
}

/* Coarse gate: may_create/may_delete/may_open all check the target inode. */
SEC("lsm/inode_permission")
int BPF_PROG(tg_inode_permission, struct inode *inode, int mask)
{
	bump(4);
	if (!(mask & MAY_WRITE))
		return 0;
	/* Only directory-level decisions are handled here; file writes are
	 * handled by file_permission, which has dentry context. */
	return decide_dir(inode, TG_OP_INODE_PERM);
}

SEC("lsm/inode_create")
int BPF_PROG(tg_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return decide_dir(dir, TG_OP_CREATE);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(tg_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return decide_dir(dir, TG_OP_MKDIR);
}

SEC("lsm/inode_unlink")
int BPF_PROG(tg_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	int ret = decide(dentry_inode(dentry), dentry_parent(dentry), TG_OP_UNLINK);
	if (ret)
		return ret;
	return decide_dir(dir, TG_OP_UNLINK);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(tg_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	int ret = decide(dentry_inode(dentry), dentry_parent(dentry), TG_OP_RMDIR);
	if (ret)
		return ret;
	return decide_dir(dir, TG_OP_RMDIR);
}

SEC("lsm/inode_rename")
int BPF_PROG(tg_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	int ret;
	/* Source inode: protects single-file rules and hard-link aliases. */
	ret = decide(dentry_inode(old_dentry), dentry_parent(old_dentry), TG_OP_RENAME);
	if (ret)
		return ret;
	/* Target inode: renaming over an existing protected file. */
	ret = decide(dentry_inode(new_dentry), dentry_parent(new_dentry), TG_OP_RENAME);
	if (ret)
		return ret;
	ret = decide_dir(old_dir, TG_OP_RENAME);
	if (ret)
		return ret;
	return decide_dir(new_dir, TG_OP_RENAME);
}

SEC("lsm/inode_link")
int BPF_PROG(tg_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry)
{
	int ret;
	/* Linking a protected file elsewhere creates a bypass alias, so the
	 * source inode must be checked too. */
	ret = decide(dentry_inode(old_dentry), NULL, TG_OP_LINK);
	if (ret)
		return ret;
	ret = decide(dentry_inode(new_dentry), NULL, TG_OP_LINK);
	if (ret)
		return ret;
	return decide_dir(dir, TG_OP_LINK);
}

SEC("lsm/inode_setattr")
int BPF_PROG(tg_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	return decide(dentry_inode(dentry), dentry_parent(dentry), TG_OP_SETATTR);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(tg_inode_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	return decide(dentry_inode(dentry), dentry_parent(dentry), TG_OP_SETXATTR);
}

/* Writable mmap bypasses write(), so it needs its own gate. */
SEC("lsm/mmap_file")
int BPF_PROG(tg_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	struct dentry *de;

	if (!(prot & PROT_WRITE))
		return 0;
	de = BPF_CORE_READ(file, f_path.dentry);
	return decide(BPF_CORE_READ(file, f_inode), dentry_parent(de), TG_OP_MMAP);
}

SEC("lsm/file_mprotect")
int BPF_PROG(tg_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct file *file;
	struct dentry *de;

	if (!(prot & PROT_WRITE))
		return 0;
	file = BPF_CORE_READ(vma, vm_file);
	if (!file)
		return 0;
	de = BPF_CORE_READ(file, f_path.dentry);
	return decide(BPF_CORE_READ(file, f_inode), dentry_parent(de), TG_OP_MPROTECT);
}

#define S_IFMT 0170000
#define S_IFDIR 0040000

/*
 * Protection inheritance.
 *
 * When a new inode is instantiated inside a protected directory, index it
 * immediately and inherit the parent's grant. This closes the window where a
 * freshly created subtree existed on disk but was not yet in the kernel index
 * (previously up to one heartbeat), which made a release creating a nested
 * directory fail its own writes until userspace refreshed the index.
 *
 * The hook runs on every dentry instantiation, so the fast path is a single
 * lookup of the parent directory: unprotected paths pay only that probe.
 */
SEC("lsm/d_instantiate")
int BPF_PROG(tg_d_instantiate, struct dentry *dentry, struct inode *inode)
{
	struct inode *parent;
	struct inode_key k = {};
	__u8 mode;
	umode_t imode;

	if (!dentry || !inode)
		return 0;
	parent = dentry_parent(dentry);
	if (!parent)
		return 0;
	mode = inode_mode(&protected_dirs, parent);
	if (!mode)
		return 0;

	k.ino = BPF_CORE_READ(inode, i_ino);
	k.dev = inode_dev(inode);
	imode = BPF_CORE_READ(inode, i_mode);

	if ((imode & S_IFMT) == S_IFDIR) {
		if (inode_mode(&protected_dirs, inode) == mode)
			return 0;
		bpf_map_update_elem(&protected_dirs, &k, &mode, BPF_ANY);
	} else {
		if (inode_mode(&protected_files, inode) == mode)
			return 0;
		bpf_map_update_elem(&protected_files, &k, &mode, BPF_ANY);
	}
	inherit_grant(parent, inode);
	return 0;
}

/*
 * The eBPF object must declare a GPL-compatible license to use the
 * GPL-only probe helpers (BPF_CORE_READ -> bpf_probe_read_kernel) and
 * ring buffer reservation. The userspace Go code stays Apache-2.0; this
 * single translation unit is dual-licensed BSD/GPL, the usual arrangement
 * for CO-RE programs loaded into the Linux kernel.
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";
