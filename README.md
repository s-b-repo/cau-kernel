# cau-kernel

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
baseline — a loaded module, a new taint flag (e.g. an unsigned/out-of-tree
module), a newly-exposed kernel-memory channel or pinned eBPF object, a hardening
regression, or a **hidden-module suspect** (present in `/sys/module` but missing
from `/proc/modules`). Run it from a timer, or on a verified boot, and route the
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

## What it reads

| Area | Signals |
|---|---|
| Modules | `/proc/modules` vs `/sys/module` cross-view (hidden-module reconciliation), refcounts, dependents |
| Taint | `/proc/sys/kernel/tainted`, decoded with the unsigned-module (E), out-of-tree (O), force-load (F), live-patch (K) and OOPS (D) bits called out |
| eBPF surface | bpffs mounts, pinned maps/programs, JIT-harden and `unprivileged_bpf_disabled` sysctls |
| Kernel memory | presence + mode of `/dev/mem`, `/dev/kmem`, `/dev/port`, `/proc/kcore`; lockdown |
| Posture | `kptr_restrict`, `dmesg_restrict`, `kexec_load_disabled`, `modules_disabled`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `ptrace_scope`, `perf_event_paranoid`; lockdown mode; LSM list; IMA presence |

Everything degrades honestly: a node that needs more privilege than the caller
has is recorded as a warning, never a silent gap. Signed baselines (Ed25519,
key off the host) make drift detection tamper-resistant — an attacker who
rewrites the baseline cannot forge its signature.

## Honest scope

Shipped and building: the detection sensor, boot attestation (TPM/IMA/kdump
drift), the BPF-LSM enforcement guard **and** the kernel-module backend (CI
compiles both). Still open, by honesty:

- **Rich per-inode/path BPF-LSM policy** — the CO-RE variant (needs libbpf-dev +
  a generated `vmlinux.h`); the recipe is in [`bpf/README.md`](bpf/README.md). The
  shipped guard is a global execution-freeze, not per-file policy yet.
- **vkernel** — KVM/QEMU guest introspection (driven from the hypervisor, needs a
  VMM + libvmi); documented, not built here.
- **kdump *capture*** — this sensor reports crash-capture *readiness*; forcing a
  kdump snapshot on tamper is a privileged, destructive action left to the
  operator's response policy, not performed by the sensor.

Those need hardware/kernel environments (VMM, Secure Boot, a crash kernel) a CI
or sandbox build cannot fully exercise; they are tracked in the engine's plan.

## License

MIT (userspace). The BPF-LSM program is GPL-2.0, as the kernel requires for LSM
hooks.
