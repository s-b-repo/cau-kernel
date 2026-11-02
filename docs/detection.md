# Detection

The default binary reads kernel state read-only and reports it, or diffs it
against a signed baseline. All commands take `--root` (default `/`) so they can
run against a fixture tree, and `--format text|json`.

## `cau-kernel inventory`

A full snapshot:

- **Modules** — `/proc/modules` (name, size, refcount, dependents, state) with a
  `/sys/module` **cross-view**. A module present in `/sys/module` (with an
  `initstate`) but absent from `/proc/modules` is a **hidden-module suspect** — a
  classic rootkit hides from one view but not the other.
- **Taint** — `/proc/sys/kernel/tainted`, decoded. The security-relevant bits are
  surfaced first: `E` unsigned module, `O` out-of-tree module, `F` force-loaded,
  `R` force-unloaded, `K` live-patched, `D` kernel OOPS/BUG.
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

`drift` exits non-zero on a **security-relevant** change: a module loaded, a new
taint flag, a newly-exposed kernel-memory channel, a new pinned eBPF object, a
hardening regression (`ok`→`weak`), or a hidden-module suspect. Module removals
and benign changes are reported at `info` level (shown with `--all`). The
baseline is Ed25519-signed; without the matching `--pubkey` a tampered baseline
is still detected as a drift, and **with** `--pubkey` a tampered baseline fails
closed (a signature that no longer verifies is itself the finding).

## Honest limits

- A fully compromised kernel can lie to `/proc`/`/sys`; cross-view and the TPM/IMA
  anchors ([attestation](attestation.md)) are the hedge, not a guarantee.
- kprobe/IMA nodes under securityfs usually need root; unreadable nodes become
  warnings, so an unprivileged run reports less, never falsely "clean".
