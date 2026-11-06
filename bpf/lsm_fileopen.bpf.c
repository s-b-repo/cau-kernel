// SPDX-License-Identifier: GPL-2.0
//
// cau-kernel BPF-LSM path-aware guard.
//
// Where lsm_guard.bpf.c is a global execution freeze, this program adds per-file
// policy: it hooks lsm/file_open and denies opening any file named in
// cau_blocked_inodes, in addition to honouring the global cau_enforce freeze. A
// verified response fills the map with what it wants kept from running or being
// read again, a dropped implant for instance. Exec opens the file first, so this
// also refuses execution.
//
// The key is (device, inode), not the inode alone: inode numbers repeat across
// filesystems, so an inode-only blocklist denies an unrelated file on another
// mount. That was a nuisance when blocking was manual. It is an outage once a
// responder fills the map automatically.
//
// Self-contained like lsm_guard.bpf.c: clang plus UAPI headers. The partial
// structs carry preserve_access_index, so every field is a CO-RE relocation.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __core __attribute__((preserve_access_index))
#define EPERM 1
#define RD(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;

struct super_block { unsigned int s_dev; } __core;
struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __core;
struct file { struct inode *f_inode; } __core;

// Global freeze flag (same meaning as lsm_guard's cau_enforce).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cau_enforce SEC(".maps");

struct inode_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

// Per-file blocklist: (device, inode) -> non-zero means "deny open".
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct inode_key);
	__type(value, __u8);
} cau_blocked_inodes SEC(".maps");

// lsm/file_open fires when a file is opened; returning a negative errno denies
// the open. We respect the global freeze first, then the blocklist.
SEC("lsm/file_open")
int cau_file_open(unsigned long long *ctx)
{
	struct file *file = (void *)ctx[0];
	int prior = (int)ctx[1];
	struct inode *inode = 0;
	struct super_block *sb = 0;
	struct inode_key key = {};
	__u32 zero = 0;
	__u32 *enforce;
	__u8 *blocked;

	if (prior)
		return prior;

	enforce = bpf_map_lookup_elem(&cau_enforce, &zero);
	if (enforce && *enforce)
		return -EPERM;

	RD(inode, file->f_inode);
	if (!inode)
		return 0;
	RD(key.ino, inode->i_ino);
	RD(sb, inode->i_sb);
	if (!sb)
		return 0;
	RD(key.dev, sb->s_dev);

	blocked = bpf_map_lookup_elem(&cau_blocked_inodes, &key);
	if (blocked && *blocked)
		return -EPERM;
	return 0;
}

char _license[] SEC("license") = "GPL";
