// SPDX-License-Identifier: GPL-2.0
//
// cau-kernel BPF-LSM network-shell guard.
//
// Userspace can only find a reverse shell by polling /proc, so anything that
// runs between two scans is invisible to it. The kernel sees the moment that
// matters: bprm_check_security fires on every execve, before the new image
// runs, with the file descriptors the program is about to inherit already in
// place. A shell whose stdin and stdout are an established network socket is a
// reverse or bind shell whatever its command line says, so this hook can see
// it, and refuse it, at exec.
//
// Matching the program's name alone loses to `cp /bin/bash /tmp/x`, so a second
// policy applies the same socket test to every program. It is separate because
// inetd-style services legitimately run on socket stdio: the wiring is worth
// auditing everywhere but only safe to refuse where the operator says so.
//
// It also reports (and optionally refuses) execution of memfd-backed files, the
// fileless path nothing on disk records.
//
// Every policy is off until userspace sets it, and the program only reads.
// The fail-open rule applies: the attachment lives as long as the resident
// enforcer, so a crash lifts the policy and can never brick the host.
//
// Only AF_INET and AF_INET6 count. OpenSSH runs non-pty sessions over AF_UNIX
// socketpairs, and so do IDEs and tool harnesses; a check on "stdin is a socket"
// alone would break `ssh host cmd`.
//
// Self-contained like lsm_guard.bpf.c: clang plus UAPI headers, no libbpf-dev and
// no generated vmlinux.h. The struct definitions below are partial on purpose;
// preserve_access_index makes every field a CO-RE relocation, resolved by name
// against the running kernel's BTF at load, so offsets are never compiled in.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define __core __attribute__((preserve_access_index))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static __u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *src) = (void *)115;
static long (*bpf_ringbuf_output)(void *rb, void *data, __u64 size, __u64 flags) = (void *)130;

#define EPERM 1
#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1

// USER_HZ is the kernel's user-visible clock rate: the unit /proc/<pid>/stat's
// starttime field counts in. The kernel fixes it at 100 on every architecture
// that still ships, and it derives that field with
//
//	start_time = nsec_to_clock_t(timens_add_boottime_ns(task->start_boottime))
//
// which is the start time in nanoseconds divided by this. A reader on the
// other side (cau ps --kernel-events) compares the number against the live
// process's own starttime field, so the two must be the same unit. If this
// constant were ever wrong the comparison would simply never match, and the
// event would fall back to being context rather than evidence: it fails safe.
// The same is true of a process in a time namespace with a boot-time offset,
// which /proc adds and this does not.
#define NSEC_PER_USER_HZ 10000000ULL

// Field reads go through bpf_probe_read_kernel: the walk crosses an array of
// pointers (the fd table), which the verifier will not follow by BTF.
#define RD(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

struct qstr { const unsigned char *name; } __core;
struct dentry { struct qstr d_name; } __core;
struct path { struct dentry *dentry; } __core;
struct inode { unsigned short i_mode; } __core;
struct file {
	struct inode *f_inode;
	struct path f_path;
	void *private_data;
} __core;
struct linux_binprm { struct file *file; } __core;
struct fdtable { struct file **fd; unsigned int max_fds; } __core;
struct files_struct { struct fdtable *fdt; } __core;
// task_struct::start_boottime is the process's start time in boot-based
// nanoseconds ("Boot based time in nsecs" in the kernel's own comment). It has
// been a u64 since Linux 5.5, and BPF-LSM needs 5.7, so every kernel that can
// run this program has it in this shape.
struct task_struct { struct files_struct *files; __u64 start_boottime; } __core;
struct in6_addr { __u8 s6_addr[16]; } __core;
struct sock_common {
	unsigned short skc_family;
	unsigned char skc_state;
	__be16 skc_dport;
	__be32 skc_daddr;
	struct in6_addr skc_v6_daddr;
} __core;
struct sock { struct sock_common __sk_common; } __core;
struct socket { struct sock *sk; } __core;

enum { POLICY_NETSHELL = 0, POLICY_MEMFD = 1, POLICY_ANY = 2, POLICY_MAX = 3 };
enum { MODE_OFF = 0, MODE_AUDIT = 1, MODE_DENY = 2 };
enum { REASON_NETSHELL = 1, REASON_MEMFD = 2, REASON_NETSTDIO = 3 };

// Policy, one mode per check. Userspace sets it after load.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, POLICY_MAX);
	__type(key, __u32);
	__type(value, __u32);
} cau_policy SEC(".maps");

// Program names counted as interpreters, filled by userspace. A map rather than
// a compiled list so the set changes without rebuilding the object.
struct name_key { char name[16]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct name_key);
	__type(value, __u8);
} cau_interpreters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} cau_events SEC(".maps");

// Mirrored by Event in internal/enforce/common.go.
struct event {
	__u32 pid;        // the process (thread-group) id, as userspace names it
	__u32 tid;        // the thread that called execve
	__u32 uid;
	__u32 reason;
	__u32 denied;
	__u16 family;
	__u16 dport;
	__u8 daddr[16];
	char comm[16];
	char exe[16];
	// The process's start time in USER_HZ ticks, the same unit and the
	// same clock as field 22 of /proc/<pid>/stat. A PID alone is not an
	// identity: the log outlives processes and PIDs are reused, so an
	// event that says which process it happened to can be matched to that
	// one and to no other.
	__u64 start_ticks;
};

// inet_peer fills e when file f is a socket with an established inet peer.
static __always_inline int inet_peer(struct file *f, struct event *e)
{
	struct inode *inode = 0;
	struct socket *sock = 0;
	struct sock *sk = 0;
	unsigned short mode = 0, family = 0;
	unsigned char state = 0;

	if (!f)
		return 0;
	RD(inode, f->f_inode);
	if (!inode)
		return 0;
	RD(mode, inode->i_mode);
	if ((mode & S_IFMT) != S_IFSOCK)
		return 0;
	RD(sock, f->private_data);
	if (!sock)
		return 0;
	RD(sk, sock->sk);
	if (!sk)
		return 0;
	RD(family, sk->__sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	RD(state, sk->__sk_common.skc_state);
	if (state != TCP_ESTABLISHED)
		return 0;

	e->family = family;
	RD(e->dport, sk->__sk_common.skc_dport);
	if (family == AF_INET)
		RD(*(__be32 *)e->daddr, sk->__sk_common.skc_daddr);
	else
		RD(e->daddr, sk->__sk_common.skc_v6_daddr);
	return 1;
}

// start_ticks returns the current task's start time in USER_HZ ticks, the
// unit /proc/<pid>/stat's starttime field uses. The kernel derives that field
// from the same value this reads:
//
//	start_time = nsec_to_clock_t(timens_add_boottime_ns(task->start_boottime))
//
// A failed read leaves it zero, which is the one value no process has: an
// event that cannot say which process it happened to is context, not evidence.
static __always_inline __u64 start_ticks(void)
{
	struct task_struct *task = (void *)bpf_get_current_task();
	__u64 ns = 0;

	if (!task)
		return 0;
	RD(ns, task->start_boottime);
	if (ns == 0)
		return 0;
	return ns / NSEC_PER_USER_HZ;
}

static __always_inline void emit(struct event *e, __u32 reason, int denied)
{
	__u64 id = bpf_get_current_pid_tgid();

	// The high half of the helper's result is the thread-group id (the
	// process as userspace names it) and the low half the thread that called
	// execve. A process with threads has one of the former and many of the
	// latter, so they are reported separately: "pid" is what an operator
	// looks up in /proc, "tid" is who did it.
	e->pid = (__u32)(id >> 32);
	e->tid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->reason = reason;
	e->denied = denied;
	e->start_ticks = start_ticks();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_output(&cau_events, e, sizeof(*e), 0);
}

static __always_inline __u32 policy(__u32 which)
{
	__u32 *mode = bpf_map_lookup_elem(&cau_policy, &which);

	return mode ? *mode : MODE_OFF;
}

SEC("lsm/bprm_check_security")
int cau_netshell_guard(unsigned long long *ctx)
{
	struct linux_binprm *bprm = (void *)ctx[0];
	int prior = (int)ctx[1];
	__u32 netshell, memfd, any, mode, reason;
	struct event e = {};
	struct name_key key = {};
	struct file *file = 0;
	struct dentry *dentry = 0;
	const unsigned char *name = 0;

	// An earlier LSM already refused this exec: its answer stands.
	if (prior)
		return prior;

	netshell = policy(POLICY_NETSHELL);
	memfd = policy(POLICY_MEMFD);
	any = policy(POLICY_ANY);
	if (netshell == MODE_OFF && memfd == MODE_OFF && any == MODE_OFF)
		return 0;

	RD(file, bprm->file);
	if (!file)
		return 0;
	RD(dentry, file->f_path.dentry);
	if (!dentry)
		return 0;
	RD(name, dentry->d_name.name);
	if (!name)
		return 0;
	bpf_probe_read_kernel_str(key.name, sizeof(key.name), name);
	__builtin_memcpy(e.exe, key.name, sizeof(e.exe));

	if (memfd != MODE_OFF && key.name[0] == 'm' && key.name[1] == 'e' && key.name[2] == 'm' &&
	    key.name[3] == 'f' && key.name[4] == 'd' && key.name[5] == ':') {
		int deny = memfd == MODE_DENY;

		emit(&e, REASON_MEMFD, deny);
		return deny ? -EPERM : 0;
	}

	if (bpf_map_lookup_elem(&cau_interpreters, &key)) {
		// An interpreter follows the interpreter policy. When that policy
		// is off the any-program policy still applies, so "off" for the
		// interpreter rule is not "no rule": it is "not this rule".
		mode = netshell != MODE_OFF ? netshell : any;
		reason = REASON_NETSHELL;
	} else {
		mode = any;
		reason = REASON_NETSTDIO;
	}

	if (mode != MODE_OFF) {
		struct task_struct *task = (void *)bpf_get_current_task();
		struct files_struct *files = 0;
		struct fdtable *fdt = 0;
		struct file **fds = 0, *in = 0, *out = 0;
		unsigned int max = 0;

		RD(files, task->files);
		if (!files)
			return 0;
		RD(fdt, files->fdt);
		if (!fdt)
			return 0;
		RD(max, fdt->max_fds);
		if (max < 2)
			return 0;
		RD(fds, fdt->fd);
		if (!fds)
			return 0;
		bpf_probe_read_kernel(&in, sizeof(in), &fds[0]);
		bpf_probe_read_kernel(&out, sizeof(out), &fds[1]);
		if (inet_peer(in, &e) && inet_peer(out, &e)) {
			int deny = mode == MODE_DENY;

			emit(&e, reason, deny);
			return deny ? -EPERM : 0;
		}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
