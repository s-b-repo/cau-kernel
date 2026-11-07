# BPF-LSM enforcement

`lsm_guard.bpf.c` is the enforcement half of cau-kernel: a BPF-LSM program that
can **freeze new process execution** on a verified tamper signal. The detection
half (`cau-kernel` inventory/drift/posture) is pure userspace Go and needs none
of this; enforcement is opt-in and privileged.

## What it does

A single-entry control map (`cau_enforce`) holds a `u32` flag. The
`lsm/bprm_check_security` hook — which fires on every `execve` before the new
image runs — returns `-EPERM` for all execs while the flag is set, and allows
everything while it is clear. Userspace (a privileged responder) sets the flag
when `cau-kernel drift` reports an alert and the operator's policy says "contain
this host", and clears it to resume. It is a deliberately blunt, auditable
primitive: freeze, not fine-grained policy.

## Build (self-contained)

Needs only `clang` with a `bpf` target — no `libbpf-dev`, no `vmlinux.h`:

```sh
make verify      # compiles lsm_guard.bpf.o and checks the LSM section
```

## Load (requires root + a BPF-LSM kernel)

Loading a BPF-LSM program requires:

- root (or `CAP_BPF` + `CAP_MAC_ADMIN`),
- a kernel built with `CONFIG_BPF_LSM=y`, and
- **`bpf` present in `/sys/kernel/security/lsm`** (i.e. `lsm=...,bpf` on the
  kernel command line). Check with `cat /sys/kernel/security/lsm`.

The Go loader is implemented in `internal/enforce` (cilium/ebpf), compiled in
with the `ebpf` build tag and driven by `cau-kernel enforce run|on|off|status`.
It embeds this object, so a `make enforce` binary is self-contained. See the
repo README. (A libbpf C loader — `bpf_object__open_file` → `load` →
`bpf_program__attach_lsm` — is the equivalent path if you prefer C.)

Because the self-contained object avoids kernel-struct access, it needs no CO-RE
relocations and loads against the running kernel's BTF as-is.

## Path-aware variant, `lsm_fileopen.bpf.c`

`lsm_fileopen.bpf.c` adds **per-file policy**: it hooks `lsm/file_open` and denies
opening any file in the `cau_blocked_inodes` map (plus the global `cau_enforce`
freeze). The key is device and inode, since inode numbers repeat across
filesystems. Fields are read through CO-RE, so it is portable across kernels, and
like `lsm_netshell.bpf.c` it declares partial structs with `preserve_access_index`
rather than needing `libbpf-dev` or a generated `vmlinux.h`.

```sh
make lsm_fileopen.bpf.o lsm_netshell.bpf.o
```

Every object here builds with clang and the kernel UAPI headers alone.

`make vm-test` from the repository root proves both on the running kernel, in
QEMU, through the real verifier. The self-contained `lsm_guard` above remains the
global-freeze baseline; this is the richer policy on top.

## Sensor self-protection (CO-RE), `lsm_killguard.bpf.c`

`lsm_killguard.bpf.c` protects the sensor itself rather than the host. It hooks
`lsm/task_kill` to deny any signal — `SIGKILL` and `SIGSTOP` included, which no
user-space program can resist — sent to a process in the `cau_protected_pids`
map, and `lsm/ptrace_access_check` to deny debugger/injector attach to one. It
reads the target's `tgid` via CO-RE, and like the others needs neither
`libbpf-dev` nor a generated `vmlinux.h`:

```sh
make lsm_killguard.bpf.o
make verify-core   # also checks the task_kill + ptrace_access_check sections
```

Drive it with `cau-kernel enforce killguard|protect|unprotect|protected` (see
[`docs/enforcement.md`](../docs/enforcement.md)). It is the kernel-level
counterpart to the scanner's userspace process-name randomisation: the latter
hides the sensor from `pkill <name>`, this makes a *found* PID unkillable while
the guard is resident.

**Fail-open and honest about its limits:** the hooks die with the resident
enforcer (so protection can never brick the host, and `protect` refuses PID 1
and the enforcer's own PID); `security_task_kill` covers user-space signals, not
every kernel-internal path (e.g. the OOM killer); and, as with every program
here, a BPF-LSM load is only verifiable on a real `CONFIG_BPF_LSM` kernel — CI
proves compilation, never load.
