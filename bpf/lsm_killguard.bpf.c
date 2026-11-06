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
// Like lsm_fileopen.bpf.c this needs libbpf-dev headers and a bpftool-generated
// vmlinux.h (CO-RE); see README.md and the `core-bpf` CI job. A BPF-LSM load
// can only be verified on a real kernel with CONFIG_BPF_LSM and `bpf` in
// /sys/kernel/security/lsm.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "GPL";

// Protected processes: thread-group id (PID as users see it) -> non-zero means
// "defend". Operator-managed from userspace; empty by default.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} cau_protected_pids SEC(".maps");

static __always_inline int protected(struct task_struct *t)
{
	__u32 tgid = BPF_CORE_READ(t, tgid);
	__u8 *v = bpf_map_lookup_elem(&cau_protected_pids, &tgid);
	return v && *v;
}

// lsm/task_kill fires when a signal is delivered to task p. Return -EPERM to
// deny. We exempt signals the protected process sends within its own thread
// group, so the sensor can still manage its own workers and signal itself.
SEC("lsm/task_kill")
int BPF_PROG(cau_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	__u32 target_tgid = BPF_CORE_READ(p, tgid);
	__u32 sender_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (sender_tgid == target_tgid)
		return 0; // intra-process signalling stays allowed
	__u8 *v = bpf_map_lookup_elem(&cau_protected_pids, &target_tgid);
	if (v && *v)
		return -EPERM;
	return 0;
}

// lsm/ptrace_access_check fires when a tracer tries to attach to `child`.
// Deny if the target is protected — blocks gdb, injectors, /proc/<pid>/mem
// writes via ptrace, and similar hooking of the sensor.
SEC("lsm/ptrace_access_check")
int BPF_PROG(cau_ptrace, struct task_struct *child, unsigned int mode)
{
	if (protected(child))
		return -EPERM;
	return 0;
}
