# Detection

The default binary reads kernel state read-only and reports it, or diffs it
against a signed baseline. All commands take `--root` (default `/`) so they can
run against a fixture tree, and `--format text|json`.

## `cau-kernel inventory`

A full snapshot:

- **Modules** — `/proc/modules` (name, size, refcount, dependents, state, load
  address and the module's own taint letters when the kernel exposes them) with a
  `/sys/module` **cross-view**. A module present in `/sys/module` (with an
  `initstate`) but absent from `/proc/modules` is a **hidden-module suspect** — a
  classic rootkit hides from one view but not the other.
- **Taint** — `/proc/sys/kernel/tainted`, decoded. The security-relevant bits are
  surfaced first: `E` unsigned module, `O` out-of-tree module, `F` force-loaded,
  `R` force-unloaded, `K` live-patched, `D` kernel OOPS/BUG. A bit beyond the
  decode table is still reported (`taint-bit-<n>`) instead of being dropped.
- **eBPF surface** — bpffs mounts (`/proc/mounts`), pinned maps/programs under
  `/sys/fs/bpf`, and the `bpf_jit_harden` / `unprivileged_bpf_disabled` sysctls.
- **Kernel-memory channels** — presence and mode of `/dev/mem`, `/dev/kmem`,
  `/dev/port`, `/proc/kcore`, and lockdown.
- **Posture** — the hardening sysctls (below), lockdown mode, the active LSM list
  (`/sys/kernel/security/lsm`), and whether IMA is present.

## `cau-kernel posture`

Just the hardening posture, each knob marked `ok` or `weak` with the reason it
matters. It reports **state, not scolding**: the operator owns the policy call.

| sysctl | hardened | why |
|---|---|---|
| `kernel.kptr_restrict` | ≥1 | kernel pointer exposure via `/proc` |
| `kernel.dmesg_restrict` | 1 | unprivileged kernel-log access |
| `kernel.kexec_load_disabled` | 1 | loading a new kernel over the running one |
| `kernel.modules_disabled` | 1 | further module loading (one-way latch) |
| `kernel.unprivileged_bpf_disabled` | ≥1 | unprivileged eBPF attack surface |
| `net.core.bpf_jit_harden` | ≥1 | BPF JIT-spray hardening |
| `kernel.yama.ptrace_scope` | ≥1 | cross-process ptrace (credential theft) |
| `kernel.perf_event_paranoid` | ≥2 | `perf_event_open` exposure |

## `cau-kernel baseline` / `drift`

Record a baseline from a known-good state, then detect drift:

```sh
cau-kernel baseline --out /var/lib/cau-kernel/base.json --sign-key priv.hex
cau-kernel drift    --baseline /var/lib/cau-kernel/base.json --pubkey pub.hex
```

`drift` exits non-zero on a **security-relevant** change:

| finding | what it means |
|---|---|
| `module-added` | a module loaded since the baseline |
| `module-changed` | the **same** module name, different size or load address — an unload/reload or a DKMS rebuild under the old name |
| `taint-added` | a new taint flag |
| `taint-removed` / `taint-cleared` | a taint flag (or a security taint bit) **disappeared** — root zeroing `/proc/sys/kernel/tainted` after loading an unsigned module |
| `mem-channel` | a kernel-memory channel appeared |
| `mem-channel-mode` | a kernel-memory channel is still there but its mode changed — a `/dev/mem` that became world-writable is a new way into the kernel |
| `bpf-pinned` | a new pinned eBPF object |
| `hardening-regression` | a hardening knob weakened: `ok`→`weak`, a knob that was **unreadable** at baseline and is weak now, or a knob that changed while already weak |
| `input-unreadable` | a monitored input (`/proc/modules`, `/sys/module`, `/proc/mounts`, the taint word, the bpffs root) became unreadable — the detector is now blind there |
| `hidden-module` | in `/sys/module` but not in `/proc/modules` |

Module removals and benign changes are reported at `info` level (shown with
`--all`): a module that was unloaded (`module-removed`), a module's used-by
list that changed (`module-refs-changed`) and a kernel-memory channel that
disappeared (`mem-channel-removed`). The baseline is Ed25519-signed, and a
signed baseline **fails closed without its public key**: `drift` refuses to
compare against a baseline whose signature it cannot check, because an attacker
who can rewrite the baseline can also rewrite what it says, and a run that
reported "no drift" from an unverified baseline would be reporting what the
attacker wanted it to report. Pass `--pubkey` and a tampered baseline fails
closed too (a signature that no longer verifies is itself the finding).

A signed baseline is **domain-separated**: the signature covers the document
kind as well as the payload, so a signed drift baseline cannot be replayed as an
attestation baseline (or the other way round) even when both were signed with
the same key. Opening a baseline of the wrong kind fails before any signature
work.

## Honest limits

- A fully compromised kernel can lie to `/proc`/`/sys`; cross-view and the TPM/IMA
  anchors ([attestation](attestation.md)) are the hedge, not a guarantee.
- kprobe/IMA nodes under securityfs usually need root; unreadable nodes become
  warnings, so an unprivileged run reports less, never falsely "clean".
