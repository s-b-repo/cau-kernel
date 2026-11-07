// SPDX-License-Identifier: GPL-2.0
//
// cau-kernel BPF-LSM kill/ptrace guard (CO-RE variant).
//
// This is the kernel-level answer to "stop malware from killing or hooking the
// sensor". It hooks two LSM points:
//
//   * lsm/task_kill          — denies any signal sent to a protected process,
//                              including SIGKILL/SIGSTOP, which cannot be
//                              resisted from user space. This defeats `pkill`,
//                              `kill -9`, and kill-by-PID loops aimed at the
//                              sensor.
//   * lsm/ptrace_access_check — denies ptrace-attach to a protected process,
//                              blocking debuggers and code injectors
//                              (PTRACE_ATTACH / PTRACE_SEIZE based tampering).
//
// "Protected" is an explicit, operator-managed set of thread-group IDs in the
// cau_protected_pids map; nothing is protected until userspace adds a PID. The
// target's tgid is read via CO-RE so the program is portable across kernels.
//
// Safety / honesty (the project's fail-open rule applies):
//   * The LSM links live only as long as the resident enforcer process. If it
//     exits or is killed, the hooks detach and protection lifts — a crash can
//     never permanently brick the host. Recovery is always "stop the enforcer".
//   * For that reason the enforcer must NOT protect its own PID (the control
//     tool refuses pid 1 and its own pid); otherwise the operator could lose
//     the ability to tear the guard down.
//   * security_task_kill is consulted for user-space-originated signals; some
//     kernel-internal signals (e.g. the OOM killer) do not pass through it, so
//     this hardens against attackers, not against the kernel itself.
//
// Self-contained like lsm_fileopen.bpf.c: clang plus UAPI headers. The partial
// struct carries preserve_access_index, so tgid is a CO-RE relocation. `make
// vm-test` proves it on a real kernel, through the real verifier.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __core __attribute__((preserve_access_index))
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define EPERM 1

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;

struct task_struct { int tgid; } __core;

char LICENSE[] SEC("license") = "GPL";

// Protected processes: thread-group id (PID as users see it) -> non-zero means
// "defend". Operator-managed from userspace; empty by default.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} cau_protected_pids SEC(".maps");

static __always_inline __u32 tgid_of(struct task_struct *t)
{
	int tgid = 0;

	bpf_probe_read_kernel(&tgid, sizeof(tgid), __builtin_preserve_access_index(&t->tgid));
	return (__u32)tgid;
}

static __always_inline int protected(__u32 tgid)
{
	__u8 *v = bpf_map_lookup_elem(&cau_protected_pids, &tgid);

	return v && *v;
}

// lsm/task_kill fires when a signal is delivered to task p. Return -EPERM to
// deny. We exempt signals the protected process sends within its own thread
// group, so the sensor can still manage its own workers and signal itself.
SEC("lsm/task_kill")
int cau_task_kill(unsigned long long *ctx)
{
	struct task_struct *p = (void *)ctx[0];
	int prior = (int)ctx[4];
	__u32 target = tgid_of(p);

	if (prior)
		return prior;
	if ((__u32)(bpf_get_current_pid_tgid() >> 32) == target)
		return 0; // intra-process signalling stays allowed
	return protected(target) ? -EPERM : 0;
}

// lsm/ptrace_access_check fires when a tracer tries to attach to `child`.
// Deny if the target is protected — blocks gdb, injectors, /proc/<pid>/mem
// writes via ptrace, and similar hooking of the sensor.
SEC("lsm/ptrace_access_check")
int cau_ptrace(unsigned long long *ctx)
{
	struct task_struct *child = (void *)ctx[0];
	int prior = (int)ctx[2];

	if (prior)
		return prior;
	return protected(tgid_of(child)) ? -EPERM : 0;
}
