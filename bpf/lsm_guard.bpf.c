// SPDX-License-Identifier: GPL-2.0
//
// cau-kernel BPF-LSM guard — the enforcement half of the kernel sensor.
//
// This is a minimal, self-contained BPF-LSM program: an *execution freeze*
// latch. When the control map's enforce flag is set (by userspace on a verified
// tamper signal), the bprm_check_security hook denies every new program
// execution with -EPERM, so an attacker who has tripped the tamper detectors
// cannot spawn further processes while the operator responds. Clearing the flag
// restores normal operation. It is deliberately simple so it compiles with just
// clang + the kernel UAPI headers (no libbpf-dev, no generated vmlinux.h) and so
// its security behaviour is auditable at a glance.
//
// A richer, path-aware policy (per-inode allow/deny, read via CO-RE) is the
// production variant described in README.md; it is built against libbpf-dev and
// a bpftool-generated vmlinux.h. Loading either needs root, a kernel built with
// BPF-LSM, and "bpf" present in /sys/kernel/security/lsm (this host qualifies).

#include <linux/bpf.h>

// Minimal libbpf-compatible definitions, so this file needs no libbpf-dev. The
// shapes match the upstream macros exactly, so the production build can drop
// these and include <bpf/bpf_helpers.h> unchanged.
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

// BPF helper: map lookup is helper id 1 in the stable UAPI numbering.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

// Control map: a single u32 "enforce" flag userspace flips. 0 = allow (monitor
// only), non-zero = freeze new execution.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cau_enforce SEC(".maps");

// bprm_check_security fires on every execve, before the new image runs. An LSM
// program returns 0 to allow or a negative errno to deny; the kernel honours the
// first denial. We ignore the (CO-RE) arguments on purpose — the latch is global
// by design — and read only our own control map.
SEC("lsm/bprm_check_security")
int cau_exec_guard(unsigned long long *ctx)
{
	__u32 key = 0;
	__u32 *enforce = bpf_map_lookup_elem(&cau_enforce, &key);
	if (enforce && *enforce)
		return -1; /* -EPERM: freeze new execution under tamper response */
	return 0;          /* allow */
}

char _license[] SEC("license") = "GPL";
