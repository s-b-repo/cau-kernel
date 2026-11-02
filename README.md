# cau-kernel

Kernel-integrity sensor for the **CAU EDR** program — the kernel-level
anti-tamper work from the engine's roadmap, as its own artifact.

It has two halves:

- **Detection (userspace Go, this binary).** Reads Linux kernel state from
  `/proc` and `/sys` — loaded modules and taint, the eBPF surface, kernel-memory
  access channels, and hardening posture — and reports tamper/rootkit-relevant
  **drift against a signed baseline**. No kernel module, portable, runs anywhere.
- **Enforcement (eBPF, [`bpf/`](bpf/README.md)).** A BPF-LSM program that can
  freeze new process execution on a verified tamper signal. Opt-in, privileged,
  and separate from detection.

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

This is a **scheduled/triggered** integrity sensor plus an execution-freeze
enforcement primitive. Continuous, in-kernel real-time mediation with rich
policy, boot-measured (TPM/IMA) attestation, kdump capture, and a DKMS fallback
module are the larger roadmap items in the engine's plan; the pieces here are the
ones that stand on their own, compile, and are tested. See [`bpf/README.md`](bpf/README.md)
for the enforcement build/load requirements.

## License

MIT (userspace). The BPF-LSM program is GPL-2.0, as the kernel requires for LSM
hooks.
