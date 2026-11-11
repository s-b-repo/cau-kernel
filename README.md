# cau-kernel

[![ci](https://github.com/s-b-repo/cau-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/s-b-repo/cau-kernel/actions/workflows/ci.yml)

Kernel-integrity sensor for the **CAU EDR** program — the kernel-level
anti-tamper work from the engine's roadmap, as its own artifact.

It has two halves:

- **Detection (userspace Go, this binary).** Reads Linux kernel state from
  `/proc` and `/sys` — loaded modules and taint, the eBPF surface, kernel-memory
  access channels, and hardening posture — and reports tamper/rootkit-relevant
  **drift against a signed baseline**. No kernel module, portable, runs anywhere.
- **Boot attestation (userspace Go, `cau-kernel attest`).** Records and verifies
  TPM PCRs, the IMA runtime-measurement log summary, and kdump readiness against
  a signed baseline — a PCR that changed means the boot chain differs.
- **Enforcement, two backends.** Both implement the same execution-freeze
  primitive; pick per host:
  - [`bpf/`](bpf/README.md) + `cau-kernel enforce` — a **BPF-LSM** program with a
    cilium/ebpf loader. The safer default; `ebpf` build tag (`make enforce`).
    Ships a path-aware CO-RE per-inode blocklist (`enforce run --core`), opt-in
    — see the *Honest scope* section below.
  - [`kmod/`](kmod/README.md) — a **loadable kernel module** (kretprobe
    mediation). *More capable than eBPF* (arbitrary in-kernel C, no verifier,
    hooks eBPF can't reach) for where BPF-LSM cannot serve — at the cost of
    out-of-tree risk and kernel taint. DKMS-packaged, signed for Secure Boot.

> Reference docs: the engine repository **[s-b-repo/cau](https://github.com/s-b-repo/cau)**,
> whose `PLAN.md` → *"Kernel-level support & anti-tamper"* and *"Sensor
> self-protection"* sections this implements, and whose `cau selftest` /
> `cau update` establish the same Ed25519 trust anchor used here for signed
> baselines.

## Install

```sh
go build -o cau-kernel .      # pure Go, standard library only
```

## Use

```sh
# A full snapshot of the kernel state the sensor watches.
cau-kernel inventory

# Just the hardening posture (state, not nagging).
cau-kernel posture

# Record a signed baseline on a known-good boot, then detect drift later.
cau-kernel baseline --out /var/lib/cau-kernel/baseline.json --sign-key priv.hex
cau-kernel drift    --baseline /var/lib/cau-kernel/baseline.json --pubkey pub.hex
```

`drift` exits non-zero when a **security-relevant** change appears since the
baseline — a loaded module, a module **swapped in place** under the same name,
a taint flag that appeared **or was cleared** (root zeroing the taint word after
an unsigned module), a newly-exposed kernel-memory channel or pinned eBPF
object, a hardening regression, a monitored input that went **unreadable**, or a
**hidden-module suspect** (present in `/sys/module` but missing from
`/proc/modules`). Run it from a timer, or on a verified boot, and route the
alert to the console.

## Enforcement (eBPF build)

```sh
make enforce                 # compile the BPF object + build with -tags ebpf (needs clang)
sudo ./cau-kernel enforce run     # resident: attach the BPF-LSM guard (state: allow)
sudo ./cau-kernel enforce on      # freeze: deny every new execve
sudo ./cau-kernel enforce off     # release
./cau-kernel enforce status       # report the current state
```

`run` holds the LSM attachment and pins the control map to bpffs; `on`/`off`/
`status` flip or read that pinned map. If `run` dies, the program detaches and
execution is no longer frozen — **fail-open**, so a crash can never brick the
host. Attaching needs root (or `CAP_BPF` + `CAP_MAC_ADMIN`) and a kernel with
`CONFIG_BPF_LSM` and `bpf` in `/sys/kernel/security/lsm`. The default binary
(built without `-tags ebpf`) has no eBPF dependency and reports that enforcement
is unavailable.

A pin in bpffs outlives the process that made it, so a resident that was killed
left a pin behind and the next one was refused with "another enforcer is
already resident". The resident now holds an advisory lock as well, which the
kernel releases when the process dies however it dies: a pin that is still
there with the lock free belonged to a resident that is gone, and it is
replaced. Stopping the resident is the whole recovery.

### The guard's event log

`cau-kernel enforce netshell --log <file>` writes one JSON object per line, and
the engine's `cau ps --kernel-events` reads them. Each line says:

| Field | What it is |
|---|---|
| `pid` | the process (thread-group) id, as an operator looks it up in `/proc` |
| `tid` | the thread that called `execve` |
| `tgid` | the process id under the name older readers expect — the same number as `pid` |
| `uid`, `reason`, `denied`, `peer`, `comm`, `exe` | who ran what, from where |
| `start_ticks` | the process's start time in USER_HZ ticks: the same clock and unit as field 22 of `/proc/<pid>/stat` |
| `time` | when the guard read the event (UTC) |

`start_ticks` is what makes an event an attribution rather than a
coincidence: a PID is reused and the log outlives the processes it names, so
an event that says which process it happened to can be matched to that one and
to no other. The kernel derives the number from the same value `/proc` uses,
and `make vm-test` proves on a real kernel that the event's start time equals
the live process's own `starttime` field. A guard that cannot read it (a
kernel without the field) writes the event without it, and the engine treats
such an event as context about the PID rather than as evidence.

## What it reads

| Area | Signals |
|---|---|
| Modules | `/proc/modules` vs `/sys/module` cross-view (hidden-module reconciliation), refcounts, dependents, load address, per-module taints |
| Taint | `/proc/sys/kernel/tainted`, decoded with the unsigned-module (E), out-of-tree (O), force-load (F), live-patch (K) and OOPS (D) bits called out |
| eBPF surface | bpffs mounts, pinned maps/programs, JIT-harden and `unprivileged_bpf_disabled` sysctls |
| Kernel memory | presence + mode of `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`; lockdown |
| Posture | `kptr_restrict`, `dmesg_restrict`, `kexec_load_disabled`, `modules_disabled`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `ptrace_scope`, `perf_event_paranoid`; lockdown mode; LSM list; IMA presence |

Everything degrades honestly: a node that needs more privilege than the caller
has is recorded as a warning, never a silent gap. Signed baselines (Ed25519,
key off the host) make drift detection tamper-resistant — an attacker who
rewrites the baseline cannot forge its signature. A **signed** baseline fails
closed without its public key: `drift` refuses to compare against a baseline
whose signature it cannot check, because an attacker who can rewrite the
baseline can also rewrite what it says.

## Honest scope

Shipped and building: the detection sensor, boot attestation (TPM/IMA/kdump
drift), the BPF-LSM enforcement guard **and** the kernel-module backend (CI
compiles both), and the path-aware CO-RE per-inode blocklist object. Still
open, by honesty:

- **Per-inode policy is opt-in and privileged, not a turnkey feature.** The
  shipped guard *by default* is the global execution-freeze (`enforce run`). The
  path-aware variant — `bpf/lsm_fileopen.bpf.c`, loaded with
  `enforce run --core <obj>` — adds `enforce block|unblock|blocked` on top,
  denying individual files by device+inode through `lsm/file_open`; see
  [`docs/enforcement.md`](docs/enforcement.md). It compiles with plain
  `clang -target bpf` (no `libbpf-dev`, no generated `vmlinux.h`), and it needs
  an `ebpf` build plus root (or `CAP_BPF` + `CAP_MAC_ADMIN`) and a
  `CONFIG_BPF_LSM`/CO-RE-capable kernel to *load*: CI proves only that it
  builds, never that it attaches.
- **vkernel** — KVM/QEMU guest introspection (driven from the hypervisor, needs a
  VMM + libvmi); documented, not built here.
- **kdump *capture*** — this sensor reports crash-capture *readiness*; forcing a
  kdump snapshot on tamper is a privileged, destructive action left to the
  operator's response policy, not performed by the sensor.

Those need hardware/kernel environments (VMM, Secure Boot, a crash kernel, a
loadable BPF-LSM host) a CI or sandbox build cannot fully exercise; they are
tracked in the engine's plan.

## Development

```sh
make build          # the default sensor (pure Go, builds anywhere)
make test           # go test -race
make enforce        # build with eBPF enforcement (needs clang + the object)
make regex-audit    # the bug-shape sweep; needs the engine checkout beside this tree
```

The sweep for swallowed errors, unbounded allocations and broken conditions
lives in the engine repository (`scripts/regex-audit.py`): one tool and one
baseline cover both trees, and the baseline records this tree's hits under the
name it has there (`cau-kernel/…`). `CAU_ENGINE` points at that checkout, and
the target fails loudly when it is not where it says — a sweep that cannot run
must never pass by not running.

## Documentation

Full docs are in [`docs/`](docs/): [architecture](docs/architecture.md),
[detection](docs/detection.md), [attestation](docs/attestation.md), and
[enforcement](docs/enforcement.md). The enforcement backends have their own
build/load notes in [`bpf/README.md`](bpf/README.md) and
[`kmod/README.md`](kmod/README.md).

## License

MIT (userspace). The BPF-LSM program is GPL-2.0, as the kernel requires for LSM
hooks.
