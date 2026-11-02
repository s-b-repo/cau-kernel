# Architecture

cau-kernel has two halves with very different risk profiles, deliberately kept
separate.

```
                         cau-kernel
          ┌───────────────────────┬────────────────────────────┐
          │   DETECTION (default) │   ENFORCEMENT (opt-in)      │
          │   userspace Go        │                             │
          │   read-only           │   BPF-LSM guard  │  kmod    │
          │   no privilege*       │   (bpf/, -tags   │ (kmod/   │
          │                       │    ebpf)         │ cau_guard│
          │   inventory           │   enforce run    │  .ko)    │
          │   posture             │   enforce on/off │          │
          │   baseline / drift    │                  │          │
          │   attest              │                  │          │
          └───────────────────────┴──────────────────┴─────────┘
             *some nodes (IMA, kprobes) need root; they degrade to warnings
```

## Detection (the default binary)

Pure Go, standard library only, no cgo, no kernel component. It reads `/proc`
and `/sys` under a configurable root (so it is testable against fixtures and can
run unprivileged), summarises the kernel's integrity-relevant state, and
compares it to a signed baseline. It cannot change anything. This is what you
deploy widely and run from a timer.

What a compromised kernel can hide from a userspace reader is the honest limit:
cross-view reconciliation (`/proc/modules` vs `/sys/module`) and TPM/IMA anchors
exist precisely because a rootkit can lie to one view but not all of them at
once.

## Enforcement (opt-in, privileged)

Two interchangeable backends implement the same primitive — an **execution
freeze** (deny all `execve`) toggled under a verified tamper response:

| | BPF-LSM (`bpf/`, default) | kernel module (`kmod/`) |
|---|---|---|
| Mechanism | `lsm/bprm_check_security` eBPF program | kretprobe on `security_bprm_check` |
| Power | verifier-bounded, LSM hooks only | arbitrary in-kernel C, any hook |
| Safety | cannot crash the kernel; auto-detaches | can panic; taints the kernel |
| Build | `-tags ebpf` (cilium/ebpf) | out-of-tree module, DKMS |
| Default? | yes | only where BPF-LSM cannot serve |

The BPF-LSM guard is the safe default. The module is the "more capable where
BPF-LSM cannot serve" backend — more powerful, less safe — for kernels without
`CONFIG_BPF_LSM` or hooks eBPF cannot reach. Both are **fail-open**: if the
resident enforcer process dies, the attachment drops and execution is no longer
frozen, so a bug can never permanently brick the host.

## Trust model

- Baselines (drift, attest) and release artifacts are **Ed25519-signed**; the
  key is off the host. Verification is fail-closed.
- The kernel module, under Secure Boot, must be signed by an enrolled MOK key or
  the kernel refuses it — the same "nothing privileged loads unverified" posture
  as the engine's signed releases.
- The sensor trusts TPM PCRs and the IMA log as boot-time anchors a running
  kernel cannot rewrite retroactively.

## Relationship to the `cau` engine

cau-kernel consumes the same ideas (signed baselines, measure-or-don't-ship,
honest scope) and is referenced from the engine's `PLAN.md` kernel section. It
does not import the engine; it is a standalone sensor that a console (or a
timer, or a boot hook) drives alongside `cau scan`.
