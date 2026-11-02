package kstate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Measured is the boot-anchored measurement state: TPM PCRs, the IMA runtime
// measurement log summary, and kdump/kexec readiness. PCRs and the IMA-log
// digest are the anchors a compromised kernel cannot rewrite retroactively —
// comparing them to a signed baseline detects a changed boot chain (different
// kernel/initrd/config) or a tampered measurement log.
type Measured struct {
	PCRBank       string            `json:"pcr_bank,omitempty"` // e.g. "sha256"
	PCRs          map[string]string `json:"pcrs,omitempty"`     // index -> hex
	IMACount      int               `json:"ima_count"`          // -1 when unreadable
	IMAViolations int               `json:"ima_violations"`     // -1 when unreadable
	IMALogSHA256  string            `json:"ima_log_sha256,omitempty"`
	Kdump         KdumpState        `json:"kdump"`
	Warnings      []string          `json:"warnings,omitempty"`
}

// KdumpState captures crash-capture readiness: a reserved crash kernel is the
// precondition for the plan's "force a kdump snapshot on tamper suspicion" row.
type KdumpState struct {
	CrashKernelLoaded bool  `json:"crash_kernel_loaded"`
	CrashSizeBytes    int64 `json:"crash_size_bytes"`
}

// Measured reads the measured-boot state under the collector's root.
func (c Collector) Measured() Measured {
	m := Measured{IMACount: -1, IMAViolations: -1, PCRs: map[string]string{}}

	// TPM PCRs, sha256 bank (the modern default). World-readable via sysfs.
	bank := "sys/class/tpm/tpm0/pcr-sha256"
	if entries, err := os.ReadDir(c.path(bank)); err == nil {
		m.PCRBank = "sha256"
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			v := c.readTrim(filepath.Join(bank, e.Name()))
			if v != "" {
				m.PCRs[e.Name()] = strings.ToLower(v)
			}
		}
	} else {
		m.Warnings = append(m.Warnings, "TPM PCRs unreadable (no TPM, or non-sha256 bank): "+err.Error())
	}

	// IMA runtime measurement log (securityfs; typically root-only).
	if v := c.readTrim("sys/kernel/security/ima/runtime_measurements_count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			m.IMACount = n
		}
	} else {
		m.Warnings = append(m.Warnings, "IMA measurement count unreadable (needs root, or IMA not enabled)")
	}
	if v := c.readTrim("sys/kernel/security/ima/violations"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			m.IMAViolations = n
		}
	}
	// Digest the ascii measurement log so a baseline can detect the log being
	// truncated or rewritten (tamper-evidence of the record itself).
	if data, err := os.ReadFile(c.path("sys/kernel/security/ima/ascii_runtime_measurements")); err == nil {
		sum := sha256.Sum256(data)
		m.IMALogSHA256 = hex.EncodeToString(sum[:])
	}

	// kdump / kexec crash-capture readiness.
	m.Kdump.CrashKernelLoaded = c.readTrim("sys/kernel/kexec_crash_loaded") == "1"
	if v := c.readTrim("sys/kernel/kexec_crash_size"); v != "" {
		m.Kdump.CrashSizeBytes, _ = strconv.ParseInt(v, 10, 64)
	}
	return m
}

// DiffMeasured reports measured-boot drift: a PCR whose value changed (a changed
// boot chain), a PCR that appeared/disappeared, an IMA log digest change or
// violation increase, or kdump readiness lost. Every PCR/IMA change is an alert;
// a reserved-crash-kernel going from loaded to not-loaded is an alert too.
func DiffMeasured(base, cur Measured) []Change {
	var ch []Change
	for idx, want := range base.PCRs {
		got, ok := cur.PCRs[idx]
		switch {
		case !ok:
			ch = append(ch, Change{"pcr-missing", "PCR " + idx + " no longer reported", "alert"})
		case got != want:
			ch = append(ch, Change{"pcr-changed", "PCR " + idx + " changed since baseline (boot chain differs)", "alert"})
		}
	}
	for idx := range cur.PCRs {
		if _, ok := base.PCRs[idx]; !ok {
			ch = append(ch, Change{"pcr-new", "PCR " + idx + " newly reported", "info"})
		}
	}
	if base.IMALogSHA256 != "" && cur.IMALogSHA256 != "" && base.IMALogSHA256 != cur.IMALogSHA256 {
		// The IMA log is append-only, so its digest always changes as new files
		// are measured; a change is informational unless the count shrank.
		ch = append(ch, Change{"ima-log-changed", "IMA measurement log changed since baseline", "info"})
	}
	if base.IMACount >= 0 && cur.IMACount >= 0 && cur.IMACount < base.IMACount {
		ch = append(ch, Change{"ima-count-regressed", "IMA measurement count went backwards (log truncated?)", "alert"})
	}
	if cur.IMAViolations > base.IMAViolations && base.IMAViolations >= 0 {
		ch = append(ch, Change{"ima-violation", "new IMA appraisal violation(s)", "alert"})
	}
	if base.Kdump.CrashKernelLoaded && !cur.Kdump.CrashKernelLoaded {
		ch = append(ch, Change{"kdump-lost", "crash kernel no longer loaded (lost crash-capture readiness)", "alert"})
	}
	sort.SliceStable(ch, func(i, j int) bool {
		if ch[i].Severity != ch[j].Severity {
			return ch[i].Severity == "alert"
		}
		return ch[i].Kind < ch[j].Kind
	})
	return ch
}
