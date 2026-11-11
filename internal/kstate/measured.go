package kstate

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// hashFile returns the hex SHA-256 of a file, read in a stream. The file is
// never held in memory: the files digested here are the ones that grow without
// bound.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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

// pcrBanks lists the PCR bank directories sysfs exposes, in preference order
// (sha256 is the modern default, sha1 is what old TPM 1.2 parts show).
var pcrBanks = []string{"sha256", "sha1", "sha384", "sha512"}

// pcrBank reads the first readable PCR bank under the collector's root and
// reports which algorithm it read. Recording the bank matters: comparing a
// sha256 baseline against a sha1 current yields two disjoint maps, which the
// naive diff would read as "every PCR vanished", so the bank itself is part of
// the measured state.
func (c Collector) pcrBank() (bank string, pcrs map[string]string, ok bool) {
	for _, alg := range pcrBanks {
		dir := "sys/class/tpm/tpm0/pcr-" + alg
		entries, err := os.ReadDir(c.path(dir))
		if err != nil { // audit:ok the next bank is tried; "no bank readable" is warned about below
			continue
		}
		got := map[string]string{}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if v := c.readTrim(filepath.Join(dir, e.Name())); v != "" {
				got[e.Name()] = strings.ToLower(v)
			}
		}
		if len(got) == 0 {
			continue
		}
		return alg, got, true
	}
	return "", nil, false
}

// Measured reads the measured-boot state under the collector's root.
func (c Collector) Measured() Measured {
	m := Measured{IMACount: -1, IMAViolations: -1, PCRs: map[string]string{}}

	// TPM PCRs, whichever bank the TPM exposes.
	if bank, pcrs, ok := c.pcrBank(); ok {
		m.PCRBank = bank
		for idx, v := range pcrs {
			m.PCRs[idx] = v
		}
	} else {
		m.Warnings = append(m.Warnings, "TPM PCRs unreadable (no TPM, or unsupported bank "+strings.Join(pcrBanks, "/")+")")
	}

	// IMA runtime measurement log (securityfs; typically root-only).
	if v := c.readTrim("sys/kernel/security/ima/runtime_measurements_count"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			m.IMACount = n
		} else {
			m.Warnings = append(m.Warnings, "IMA measurement count unparseable: "+err.Error())
		}
	} else {
		m.Warnings = append(m.Warnings, "IMA measurement count unreadable (needs root, or IMA not enabled)")
	}
	if v := c.readTrim("sys/kernel/security/ima/violations"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			m.IMAViolations = n
		} else {
			m.Warnings = append(m.Warnings, "IMA violations unparseable: "+err.Error())
		}
	}
	// Digest the ascii measurement log so a baseline can detect the log being
	// truncated or rewritten (tamper-evidence of the record itself).
	//
	// The log is streamed, not read: it grows without bound and is routinely
	// hundreds of megabytes on a long-running host, and the sensor runs on the
	// host it watches. Reading it whole would be a memory spike on the very
	// command an operator runs under pressure.
	if sum, err := hashFile(c.path("sys/kernel/security/ima/ascii_runtime_measurements")); err == nil {
		m.IMALogSHA256 = sum
	}

	// kdump / kexec crash-capture readiness.
	m.Kdump.CrashKernelLoaded = c.readTrim("sys/kernel/kexec_crash_loaded") == "1"
	if v := c.readTrim("sys/kernel/kexec_crash_size"); v != "" {
		n, perr := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if perr != nil {
			// A parse failure that silently records 0 would look like "no
			// crash kernel reserved" — the opposite of the truth.
			m.Warnings = append(m.Warnings, "kexec_crash_size unparseable: "+perr.Error())
		} else {
			m.Kdump.CrashSizeBytes = n
		}
	}
	return m
}

// DiffMeasured reports measured-boot drift: a PCR whose value changed (a changed
// boot chain), a PCR that appeared/disappeared, an IMA log digest change or
// violation increase, or kdump readiness lost. Every PCR/IMA change is an alert;
// a reserved-crash-kernel going from loaded to not-loaded is an alert too.
func DiffMeasured(base, cur Measured) []Change {
	var ch []Change
	// A different PCR bank means the two readings are not comparable at all;
	// treating the disjoint maps as "all PCRs missing" both overstates and
	// understates what happened.
	if base.PCRBank != cur.PCRBank {
		sev := "info"
		if base.PCRBank != "" && cur.PCRBank != "" {
			sev = "alert"
		}
		detail := "PCR bank changed since baseline: " + bankLabel(base.PCRBank) + " -> " + bankLabel(cur.PCRBank)
		if sev == "info" {
			detail += " (one side unreadable)"
		}
		ch = append(ch, Change{"pcr-bank-changed", detail, sev})
	}
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
	// A baseline recorded unprivileged stores -1 for the IMA counters; clamping
	// that to 0 keeps the "violations appeared" delta visible, while a current
	// reading of -1 (still unreadable) must not manufacture an alert.
	if cur.IMAViolations >= 0 && cur.IMAViolations > max(base.IMAViolations, 0) {
		ch = append(ch, Change{"ima-violation", "new IMA appraisal violation(s)", "alert"})
	}
	if base.Kdump.CrashKernelLoaded && !cur.Kdump.CrashKernelLoaded {
		ch = append(ch, Change{"kdump-lost", "crash kernel no longer loaded (lost crash-capture readiness)", "alert"})
	}
	// Measured inputs that became unreadable mute this half of the sensor: the
	// warning set is part of the diff too.
	baseWarn := stringSet(base.Warnings)
	for _, w := range cur.Warnings {
		if baseWarn[w] {
			continue
		}
		ch = append(ch, Change{"measured-input-lost", "monitored input no longer readable: " + w, warningSeverity(w)})
	}
	sort.SliceStable(ch, func(i, j int) bool {
		if ch[i].Severity != ch[j].Severity {
			return ch[i].Severity == "alert"
		}
		return ch[i].Kind < ch[j].Kind
	})
	return ch
}

func bankLabel(b string) string {
	if b == "" {
		return "unreadable"
	}
	return b
}
