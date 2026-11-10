package kstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func measuredFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	w := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("sys/class/tpm/tpm0/pcr-sha256/0", "AABB\n")
	w("sys/class/tpm/tpm0/pcr-sha256/7", "CCDD\n")
	w("sys/kernel/security/ima/runtime_measurements_count", "42\n")
	w("sys/kernel/security/ima/violations", "0\n")
	w("sys/kernel/security/ima/ascii_runtime_measurements", "10 abc ima-ng sha256:deadbeef /init\n")
	w("sys/kernel/kexec_crash_loaded", "1\n")
	w("sys/kernel/kexec_crash_size", "134217728\n")
	return root
}

func TestMeasuredReads(t *testing.T) {
	m := Collector{Root: measuredFixture(t)}.Measured()
	if m.PCRBank != "sha256" || len(m.PCRs) != 2 {
		t.Fatalf("PCRs: bank=%q n=%d", m.PCRBank, len(m.PCRs))
	}
	if m.PCRs["0"] != "aabb" { // lowercased
		t.Errorf("PCR 0 = %q", m.PCRs["0"])
	}
	if m.IMACount != 42 || m.IMAViolations != 0 {
		t.Errorf("IMA count=%d violations=%d", m.IMACount, m.IMAViolations)
	}
	if m.IMALogSHA256 == "" {
		t.Error("IMA log digest not computed")
	}
	if !m.Kdump.CrashKernelLoaded || m.Kdump.CrashSizeBytes != 134217728 {
		t.Errorf("kdump: %+v", m.Kdump)
	}
}

func TestMeasuredWarnsWhenAbsent(t *testing.T) {
	m := Collector{Root: t.TempDir()}.Measured()
	if m.IMACount != -1 {
		t.Errorf("absent IMA count should be -1, got %d", m.IMACount)
	}
	if len(m.Warnings) == 0 {
		t.Error("expected warnings for an absent TPM/IMA")
	}
}

func TestDiffMeasuredAlertsOnPCRChangeAndKdumpLoss(t *testing.T) {
	base := Measured{
		PCRs:          map[string]string{"0": "aabb", "7": "ccdd"},
		IMACount:      42,
		IMAViolations: 0,
		Kdump:         KdumpState{CrashKernelLoaded: true},
	}
	cur := Measured{
		PCRs:          map[string]string{"0": "aabb", "7": "9999"}, // PCR 7 changed
		IMACount:      40,                                          // regressed
		IMAViolations: 1,                                           // new violation
		Kdump:         KdumpState{CrashKernelLoaded: false},        // kdump lost
	}
	alerts := Alerts(DiffMeasured(base, cur))
	kinds := map[string]bool{}
	for _, c := range alerts {
		kinds[c.Kind] = true
	}
	for _, want := range []string{"pcr-changed", "ima-count-regressed", "ima-violation", "kdump-lost"} {
		if !kinds[want] {
			t.Errorf("missing alert %q; got %v", want, kinds)
		}
	}
}

func TestDiffMeasuredQuietWhenStable(t *testing.T) {
	m := Measured{PCRs: map[string]string{"0": "aabb"}, IMACount: 10, Kdump: KdumpState{CrashKernelLoaded: true}}
	if len(Alerts(DiffMeasured(m, m))) != 0 {
		t.Error("stable measured state reported drift")
	}
}

// ── The PCR bank is part of the measured state ────────────────────────────────
//
// The old collector read pcr-sha256 and nothing else, so a host whose TPM only
// exposes sha1 (every TPM 1.2 part) reported "no PCRs" — indistinguishable
// from a host with no TPM at all, and a comparison against a sha256 baseline
// read as "every PCR vanished".

func TestMeasuredReadsWhicheverPCRBankTheTPMExposes(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha1/0", "AABB\n")
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha1/7", "CCDD\n")
	m := Collector{Root: root}.Measured()
	if m.PCRBank != "sha1" {
		t.Fatalf("PCR bank = %q, want sha1", m.PCRBank)
	}
	if len(m.PCRs) != 2 || m.PCRs["0"] != "aabb" {
		t.Errorf("sha1 PCRs not read: %+v", m.PCRs)
	}
	for _, w := range m.Warnings {
		if strings.Contains(w, "TPM PCRs") {
			t.Errorf("a readable sha1 bank still warned: %q", w)
		}
	}
}

func TestMeasuredPrefersSHA256OverOtherBanks(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha256/0", "1111\n")
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha1/0", "2222\n")
	m := Collector{Root: root}.Measured()
	if m.PCRBank != "sha256" || m.PCRs["0"] != "1111" {
		t.Errorf("bank preference wrong: bank=%q pcrs=%v", m.PCRBank, m.PCRs)
	}
}

func TestMeasuredSkipsAnEmptyBankAndTakesTheNext(t *testing.T) {
	root := t.TempDir()
	// A sha256 directory that exists but exposes nothing readable must not
	// shadow the sha1 bank behind it.
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha256/0", "\n")
	writeNode(t, root, "sys/class/tpm/tpm0/pcr-sha1/0", "3333\n")
	m := Collector{Root: root}.Measured()
	if m.PCRBank != "sha1" || m.PCRs["0"] != "3333" {
		t.Errorf("empty bank not skipped: bank=%q pcrs=%v", m.PCRBank, m.PCRs)
	}
}

func TestMeasuredWarnsWhenNoPCRBankIsReadable(t *testing.T) {
	m := Collector{Root: t.TempDir()}.Measured()
	if m.PCRBank != "" {
		t.Errorf("PCR bank = %q, want empty", m.PCRBank)
	}
	found := false
	for _, w := range m.Warnings {
		if strings.Contains(w, "TPM PCRs unreadable") {
			found = true
		}
	}
	if !found {
		t.Errorf("no TPM did not produce a warning: %v", m.Warnings)
	}
}

func TestDiffMeasuredReportsPCRBankChange(t *testing.T) {
	// Same PCR index, same value, different bank: the two readings are not
	// comparable, which is a finding in itself. Without it the diff would say
	// nothing (values match) or, for different indexes, that every PCR
	// vanished.
	base := Measured{PCRBank: "sha256", PCRs: map[string]string{"0": "aabb"}}
	cur := Measured{PCRBank: "sha1", PCRs: map[string]string{"0": "aabb"}}
	alerts := Alerts(DiffMeasured(base, cur))
	kinds := map[string]bool{}
	for _, c := range alerts {
		kinds[c.Kind] = true
	}
	if !kinds["pcr-bank-changed"] {
		t.Fatalf("PCR bank change not reported: %v", alerts)
	}
	if kinds["pcr-missing"] || kinds["pcr-new"] {
		t.Errorf("a bank change was also reported as PCR churn: %v", alerts)
	}
}

func TestDiffMeasuredPCRBankChangeWithOneSideUnreadableIsInfo(t *testing.T) {
	base := Measured{PCRBank: "", PCRs: map[string]string{}}
	cur := Measured{PCRBank: "sha256", PCRs: map[string]string{"0": "aabb"}}
	for _, c := range DiffMeasured(base, cur) {
		if c.Kind == "pcr-bank-changed" && c.Severity != "info" {
			t.Errorf("a half-readable comparison alerted: %+v", c)
		}
	}
}

// ── A monitored input that became unreadable must surface ───────────────────

func TestDiffMeasuredReportsLostMeasuredInput(t *testing.T) {
	base := Measured{PCRBank: "sha256", PCRs: map[string]string{"0": "aabb"}}
	cur := Measured{PCRBank: "sha256", PCRs: map[string]string{"0": "aabb"},
		Warnings: []string{"TPM PCRs unreadable (no TPM, or unsupported bank sha256/sha1/sha384/sha512)"}}
	alerts := Alerts(DiffMeasured(base, cur))
	found := false
	for _, c := range alerts {
		if c.Kind == "measured-input-lost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a lost measured input was not reported: %v", DiffMeasured(base, cur))
	}
}

func TestDiffMeasuredQuietWhenTheSameWarningWasAlreadyThere(t *testing.T) {
	w := []string{"IMA measurement count unreadable (needs root, or IMA not enabled)"}
	base := Measured{Warnings: w}
	cur := Measured{Warnings: w}
	for _, c := range DiffMeasured(base, cur) {
		if c.Kind == "measured-input-lost" {
			t.Errorf("an unchanged warning reported as lost: %+v", c)
		}
	}
}

func TestDiffMeasuredLostKdumpReadingIsAnAlert(t *testing.T) {
	// The kdump readiness is one of the measured detectors: losing the reading
	// leaves it blind, so it is an alert and not information.
	base := Measured{Kdump: KdumpState{CrashKernelLoaded: true}}
	cur := Measured{Kdump: KdumpState{CrashKernelLoaded: true},
		Warnings: []string{"kexec_crash_size unparseable: invalid syntax"}}
	alerts := Alerts(DiffMeasured(base, cur))
	found := false
	for _, c := range alerts {
		if c.Kind == "measured-input-lost" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a lost kdump reading was not reported: %v", DiffMeasured(base, cur))
	}
	if len(alerts) != 1 {
		t.Errorf("want one alert, got %v", alerts)
	}
}

// ── The IMA counters: -1 means unreadable, not zero ─────────────────────────

func TestDiffMeasuredIMAViolationWithUnreadableBaseline(t *testing.T) {
	// The baseline was recorded unprivileged (-1 violations). Violations now
	// exist: the old comparison against -1 could never fire.
	base := Measured{IMAViolations: -1, IMACount: -1}
	cur := Measured{IMAViolations: 2, IMACount: 7}
	alerts := Alerts(DiffMeasured(base, cur))
	found := false
	for _, c := range alerts {
		if c.Kind == "ima-violation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("new IMA violations against an unreadable baseline not reported: %v", alerts)
	}
}

func TestDiffMeasuredNoViolationAlertWhenStillUnreadable(t *testing.T) {
	// Reading -1 now must not manufacture an alert out of nothing.
	base := Measured{IMAViolations: 0}
	cur := Measured{IMAViolations: -1}
	for _, c := range DiffMeasured(base, cur) {
		if c.Kind == "ima-violation" {
			t.Errorf("an unreadable violation count alerted: %+v", c)
		}
	}
}

func TestMeasuredWarnsOnUnparseableCounters(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "sys/kernel/security/ima/runtime_measurements_count", "not-a-number\n")
	writeNode(t, root, "sys/kernel/security/ima/violations", "nope\n")
	writeNode(t, root, "sys/kernel/kexec_crash_loaded", "1\n")
	writeNode(t, root, "sys/kernel/kexec_crash_size", "not-a-size\n")
	m := Collector{Root: root}.Measured()
	warnings := strings.Join(m.Warnings, "\n")
	if !strings.Contains(warnings, "IMA measurement count unparseable") {
		t.Errorf("unparseable IMA count not warned: %v", m.Warnings)
	}
	if !strings.Contains(warnings, "IMA violations unparseable") {
		t.Errorf("unparseable IMA violations not warned: %v", m.Warnings)
	}
	// A silently zeroed crash size would read as "no crash kernel reserved".
	if !strings.Contains(warnings, "kexec_crash_size unparseable") {
		t.Errorf("unparseable crash size not warned: %v", m.Warnings)
	}
	if m.IMACount != -1 || m.IMAViolations != -1 {
		t.Errorf("unparseable counters not reported as unreadable: count=%d violations=%d", m.IMACount, m.IMAViolations)
	}
	// The crash kernel is loaded; only its size was unreadable.
	if !m.Kdump.CrashKernelLoaded {
		t.Error("crash-kernel readiness lost because the size was unparseable")
	}
}
