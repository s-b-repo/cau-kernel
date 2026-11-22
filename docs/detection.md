# Detection

The default binary reads kernel state and reports it, or diffs it against a
signed baseline. Detection commands take `--root` (default `/`) to support
fixture trees. Inventory and posture also take `--format text|json`.

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
  Linux builds with the `ebpf` tag also inventory loaded programs and
  links on the live host. Program type and kernel bytecode tag identify
  programs, and link type and available attach type identify relationships
  to those programs. The comparison preserves duplicate counts without
  relying on boot-specific IDs. Permission errors and incomplete tables
  appear as coverage loss against a readable baseline.
  [Linux BPF object inventory](https://docs.kernel.org/userspace-api/ebpf/syscall.html)
- **Kernel hook registrations** — kprobe registrations, active ftrace callback
  records, livepatch enabled and transition state, and the ordered active LSM
  list. Text shows source and coverage. JSON includes the observed records.
  Absolute hook addresses are omitted from comparison.
  [Kprobes](https://docs.kernel.org/trace/kprobes.html),
  [ftrace](https://docs.kernel.org/trace/ftrace.html),
  [livepatch](https://docs.kernel.org/livepatch/livepatch.html),
  [LSM](https://docs.kernel.org/admin-guide/LSM/index.html).
- **Kernel-memory channels** — presence and mode of `/dev/mem`, `/dev/kmem`,
  `/dev/port`, `/proc/kcore`, and lockdown.
- **Posture** — the hardening sysctls (below), lockdown mode, the active LSM list
  (`/sys/kernel/security/lsm`), and whether IMA is present.

## `cau-kernel posture`

Each observed setting is marked `ok` or `weak` with the reason it matters.
Unmeasured or malformed settings are marked `unknown`.

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
| `module.sig_enforce` | enabled | signature enforcement reported by `/sys/module/module/parameters/sig_enforce` |

## `cau-kernel baseline` / `drift`

Record a baseline from a known-good state, then detect drift:

```sh
cau-kernel baseline --out /var/lib/cau-kernel/base.json --sign-key priv.hex
cau-kernel drift    --baseline /var/lib/cau-kernel/base.json --pubkey pub.hex
```

Add `--format json` to export a version 1 drift report. It contains alert and
information counts, the baseline verification result, observation time and
per-hook coverage. Detailed findings remain available in the text output.
The report carries `scope: live` for the Linux host and `scope: fixture`
for an alternate root. On the live host, `boot_id` identifies the current
kernel boot when procfs provides it. Partial coverage limits the comparison
to readable sources. An unverifiable signature prevents a report from being
emitted. JSON counts include all findings regardless of the `--all` option.

`drift` exits non-zero on a **security-relevant** change:

| finding | what it means |
|---|---|
| `module-added` | a module loaded since the baseline |
| `module-changed` | the **same** module name, different size or load address — an unload/reload or a DKMS rebuild under the old name |
| `module-taints-changed` | a loaded module's kernel-reported taint flags changed, including the unsigned-module flag `E` |
| `taint-added` | a new taint flag |
| `taint-removed` / `taint-cleared` | a taint flag (or a security taint bit) **disappeared** — root zeroing `/proc/sys/kernel/tainted` after loading an unsigned module |
| `mem-channel` | a kernel-memory channel appeared |
| `mem-channel-mode` | a kernel-memory channel is still there but its mode changed — a `/dev/mem` that became world-writable is a new way into the kernel |
| `bpf-pinned` | a new pinned eBPF object |
| `hook-added` / `hook-removed` | a registration record appeared or disappeared, including changed callback counts and livepatch state |
| `hook-order-changed` | the order of the active LSM list changed |
| `hook-coverage` | a previously readable source became partial or unavailable |
| `hardening-regression` | a hardening knob weakened: `ok`→`weak`, a knob that was **unreadable** at baseline and is weak now, or a knob that changed while already weak |
| `hardening-unreadable` | an observed hardening setting became unknown |
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

Older signed baselines remain valid. Hook drift requires readable records in
both snapshots. Drift prints an informational coverage message for each source
missing from an older baseline or unreadable when it was recorded.

## Honest limits

- A fully compromised kernel can lie to `/proc`/`/sys`; cross-view and the TPM/IMA
  anchors ([attestation](attestation.md)) are the hedge, not a guarantee.
- The hook inventory reads the debugfs kprobe list, the tracefs
  `enabled_functions` table (with a legacy debugfs fallback), the sysfs
  livepatch directory, and the securityfs LSM list. Missing, unreadable or
  malformed inputs have explicit coverage states. Hook data is a snapshot
  of those sources. Unpinned eBPF programs, standalone BPF links and changes
  between snapshots are outside this collection.
