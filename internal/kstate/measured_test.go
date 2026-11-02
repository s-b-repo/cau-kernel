package kstate

import (
	"os"
	"path/filepath"
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
