# Attestation

`cau-kernel attest` records and verifies boot-anchored measurement state — the
things a running kernel cannot rewrite retroactively — against a signed baseline.

```sh
cau-kernel attest show                                   # print current state
cau-kernel attest baseline --out a.json --sign-key priv.hex
cau-kernel attest verify   --baseline a.json --pubkey pub.hex
```

## What it reads

- **TPM PCRs** (`/sys/class/tpm/tpm0/pcr-sha256/*`) — the measured-boot
  registers. These are world-readable via sysfs, so `attest show` works
  unprivileged. A PCR that **changes** between baseline and verify means the boot
  chain differs (a different kernel, initrd, bootloader config, or Secure Boot
  state) — the measured-boot tamper signal.
- **IMA** (`/sys/kernel/security/ima/`) — the runtime measurement count, the
  appraisal violation count, and a SHA-256 **digest of the measurement log**
  (`ascii_runtime_measurements`). securityfs is typically root-only; off root
  these degrade to warnings. A log that **shrank** (count regressed) or a new
  **violation** is an alert.
- **kdump readiness** (`/sys/kernel/kexec_crash_loaded`, `kexec_crash_size`) —
  whether a crash kernel is reserved and loaded, the precondition for capturing a
  snapshot on tamper. Losing readiness (`loaded`→`not loaded`) is an alert.

## Verify semantics

`attest verify` exits non-zero when:

- any baseline PCR changed or disappeared (`alert`),
- the IMA measurement count regressed or violations increased (`alert`),
- crash-capture readiness was lost (`alert`), or
- the baseline is signed and the signature does not verify against `--pubkey`
  (fail-closed).

The IMA log is append-only, so its digest changing as new files are measured is
reported at `info` (shown with `--all`), not as an alert.

## Deployment

Record the baseline on a trusted boot (ideally right after provisioning, as
root so IMA is captured), store it signed, and run `attest verify --pubkey` early
in boot or from a timer. Route an alert to the console: a changed PCR on a host
that was not reinstalled is a strong boot-tamper indicator.

## Honest limits

- This reads PCRs from sysfs; it does not perform a **remote attestation
  quote** (a TPM-signed `TPM2_Quote` with a nonce). Quote-based attestation —
  which proves freshness and binds to the TPM's attestation key — needs the TPM
  resource manager and is a larger, hardware-bound piece tracked in the plan.
- Forcing a **kdump capture** on tamper is a privileged, destructive action left
  to the operator's response policy; the sensor reports readiness, it does not
  trigger the crash.
