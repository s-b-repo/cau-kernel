# cau-kernel documentation

`cau-kernel` is the kernel-integrity sensor for the [CAU EDR](https://github.com/s-b-repo/cau)
program: it detects tampering with the Linux kernel and, optionally, enforces an
execution freeze in response. It is a separate artifact from the `cau` engine
because it is kernel-adjacent (eBPF, an optional kernel module, TPM/IMA); the
engine stays a portable, stdlib-only userspace scanner.

## Contents

- **[Architecture](architecture.md)** — the two halves (detect / enforce), the
  trust model, and what runs where.
- **[Detection](detection.md)** — `inventory`, `posture`, `baseline`, `drift`:
  modules, taint, eBPF surface, kernel-memory channels, hardening posture.
- **[Attestation](attestation.md)** — `attest`: TPM PCRs, IMA, kdump readiness
  versus a signed baseline.
- **[Enforcement](enforcement.md)** — the two interchangeable backends: the
  BPF-LSM guard (`enforce`) and the kernel module (`kmod/`), and when to pick
  which.

## One-paragraph tour

```sh
cau-kernel inventory                 # what the kernel looks like right now
cau-kernel baseline --out b.json --sign-key priv.hex
cau-kernel drift    --baseline b.json --pubkey pub.hex   # alert on tamper drift
cau-kernel attest   verify --baseline a.json --pubkey pub.hex
sudo ./cau-kernel enforce run        # (eBPF build) hold the BPF-LSM guard
sudo ./cau-kernel enforce on         # freeze new execution under tamper response
```

## Design rules (inherited from the engine)

- **Detect, don't tamper.** Detection is read-only. Enforcement is explicit,
  reversible, and fail-open on the enforcer dying.
- **Measure-or-don't-ship.** A check ships only once its false-positive behaviour
  is understood; unreadable kernel nodes degrade to warnings, never silent gaps.
- **Trust is signed.** Baselines and release artifacts are Ed25519-signed; the
  private key lives off the host. A tampered baseline fails closed.
- **Honest scope.** What needs hardware or a resident real-time kernel component
  is named as such, not stubbed and claimed done.
