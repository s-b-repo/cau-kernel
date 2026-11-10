# Attestation

`cau-kernel attest` records and verifies boot-anchored measurement state — the
things a running kernel cannot rewrite retroactively — against a signed baseline.

```sh
cau-kernel attest show                                   # print current state
cau-kernel attest baseline --out a.json --sign-key priv.hex
cau-kernel attest verify   --baseline a.json --pubkey pub.hex
```

## What it reads

- **TPM PCRs** (`/sys/class/tpm/tpm0/pcr-<alg>/*`) — the measured-boot
  registers. These are world-readable via sysfs, so `attest show` works
  unprivileged. The bank the TPM actually exposes is read (`sha256` preferred,
  then `sha1`, `sha384`, `sha512`) and **recorded with the baseline**: a TPM
  1.2 part that exposes only `sha1` used to read as "no PCRs at all", and
  comparing a `sha256` baseline against a `sha1` reading produced two disjoint
  maps that the diff read as "every PCR vanished". A PCR that **changes** between
  baseline and verify means the boot chain differs (a different kernel, initrd,
  bootloader config, or Secure Boot state) — the measured-boot tamper signal.
  A **different bank** is an alert too: the two readings are not comparable, so
  the boot chain cannot be verified from them.
- **IMA** (`/sys/kernel/security/ima/`) — the runtime measurement count, the
  appraisal violation count, and a SHA-256 **digest of the measurement log**
  (`ascii_runtime_measurements`). securityfs is typically root-only; off root
  these degrade to warnings. A log that **shrank** (count regressed) or a new
  **violation** is an alert. A baseline recorded unprivileged (counters `-1`,
  meaning "unreadable") still catches violations that appear later — the
  comparison is clamped to zero, never to the unreadable value.
- **kdump readiness** (`/sys/kernel/kexec_crash_loaded`, `kexec_crash_size`) —
  whether a crash kernel is reserved and loaded, the precondition for capturing a
  snapshot on tamper. Losing readiness (`loaded`→`not loaded`) is an alert.

## Verify semantics

`attest verify` exits non-zero when:

- any baseline PCR changed or disappeared (`alert`),
- the PCR **bank** changed (`alert` — the two readings are not comparable),
- the IMA measurement count regressed or violations increased (`alert`),
- crash-capture readiness was lost (`alert`),
- a monitored input became **unreadable** that was readable at baseline
  (`alert` for a security-relevant input: the TPM, the IMA counters, the kdump
  state) — the check is now running blind on that input, or
- the baseline is signed and the signature does not verify against `--pubkey`
  (fail-closed).

The IMA log is append-only, so its digest changing as new files are measured is
reported at `info` (shown with `--all`), not as an alert.

A signed baseline is **domain-separated**: the signature covers the document
kind as well as the payload, so a signed drift baseline cannot be replayed as an
attestation baseline (or the other way round) even when both were signed with
the same key.

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
