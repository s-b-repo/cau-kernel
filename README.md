# cau-kernel

Kernel-integrity sensor for the **CAU EDR** program — the kernel-level
anti-tamper work from the engine's roadmap, as its own artifact.

It has two halves:

- **Detection (userspace Go, this binary).** Reads Linux kernel state from
  `/proc` and `/sys` — loaded modules and taint, the eBPF surface, kernel-memory
  access channels, and hardening posture — and reports tamper/rootkit-relevant
  **drift against a signed baseline**. No kernel module, portable, runs anywhere.
- **Enforcement (eBPF, [`bpf/`](bpf/README.md) + `cau-kernel enforce`).** A
  BPF-LSM program that can freeze new process execution on a verified tamper
  signal, with a cilium/ebpf loader. Opt-in, privileged, and compiled in only
  with the `ebpf` build tag (`make enforce`) so the default binary stays
  dependency-free.

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

This is a **scheduled/triggered** integrity sensor plus an execution-freeze
enforcement primitive (load + attach + control, shipped). Still open, by
honesty: **rich per-inode/path BPF-LSM policy** (the CO-RE variant), a **DKMS**
out-of-tree fallback module, **vkernel** guest introspection, **TPM/IMA**
boot-measured attestation, and **kdump** capture. Those need hardware/kernel
environments a userspace build cannot exercise; they are tracked in the engine's
plan. The pieces here stand on their own, compile, and are tested. See
[`bpf/README.md`](bpf/README.md) for enforcement build/load requirements.

## License

MIT (userspace). The BPF-LSM program is GPL-2.0, as the kernel requires for LSM
hooks.
