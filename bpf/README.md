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

## Production variant (path-aware, CO-RE)

For per-file policy (allow/deny by inode or path, log the denied path), build
the richer program against `libbpf-dev` and a generated header:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -target bpf -O2 -g -D__TARGET_ARCH_x86 \
      -I/usr/include/$(uname -m)-linux-gnu -c lsm_fileopen.bpf.c -o lsm_fileopen.bpf.o
```

That variant reads `file->f_path` via `BPF_CORE_READ` and checks an LRU hash map
of blocked inodes. It is documented here rather than shipped half-built; the
self-contained guard above is the compiling, auditable baseline.
