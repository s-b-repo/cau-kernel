// SPDX-License-Identifier: GPL-2.0
//
// cau-kernel BPF-LSM path-aware guard (CO-RE variant).
//
// Where lsm_guard.bpf.c is a global execution freeze, this program adds
// per-inode policy: it hooks lsm/file_open and denies opening any file whose
// inode number is in the cau_blocked_inodes map, in addition to honouring the
// global cau_enforce freeze. Userspace populates cau_blocked_inodes with the
// inodes of files a verified tamper response should quarantine from access
// (e.g. a dropped implant), reading the inode via CO-RE so the program is
// portable across kernels.
//
// Unlike the self-contained lsm_guard, this needs libbpf-dev headers and a
// bpftool-generated vmlinux.h (CO-RE). See README.md / the `core-bpf` CI job.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

// Global freeze flag (same meaning as lsm_guard's cau_enforce).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cau_enforce SEC(".maps");

// Per-inode blocklist: inode number -> non-zero means "deny open".
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} cau_blocked_inodes SEC(".maps");

// lsm/file_open fires when a file is opened; returning a negative errno denies
// the open. We respect the global freeze first, then the per-inode blocklist.
SEC("lsm/file_open")
int BPF_PROG(cau_file_open, struct file *file)
{
	__u32 zero = 0;
	__u32 *enforce = bpf_map_lookup_elem(&cau_enforce, &zero);
	if (enforce && *enforce)
		return -EPERM;

	__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
	__u8 *blocked = bpf_map_lookup_elem(&cau_blocked_inodes, &ino);
	if (blocked && *blocked)
		return -EPERM;

	return 0;
}
