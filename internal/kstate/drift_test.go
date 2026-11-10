package kstate

import (
	"strings"
	"testing"
)

func diffKinds(changes []Change) map[string]bool {
	k := map[string]bool{}
	for _, c := range changes {
		k[c.Kind] = true
	}
	return k
}

func TestDiffFlagsSecurityDrift(t *testing.T) {
	base := Snapshot{
		Modules:     []Module{{Name: "nf_tables"}},
		Taint:       TaintState{Flags: []string{"W: warning issued"}},
		MemChannels: []MemChannel{{Path: "/dev/mem", Present: false}},
		BPF:         BPFSurface{PinnedObjects: []string{"/sys/fs/bpf/known"}},
		Posture:     Posture{Observations: []PostureNote{{Key: "kernel/kptr_restrict", Level: "ok"}}},
	}
	cur := Snapshot{
		Modules:     []Module{{Name: "nf_tables"}, {Name: "evil"}},                                 // added
		Taint:       TaintState{Flags: []string{"W: warning issued", "E: unsigned module loaded"}}, // new taint
		MemChannels: []MemChannel{{Path: "/dev/mem", Present: true}},                               // newly present
		BPF:         BPFSurface{PinnedObjects: []string{"/sys/fs/bpf/known", "/sys/fs/bpf/injected"}},
		Hidden:      []string{"sneaky"},
		Posture:     Posture{Observations: []PostureNote{{Key: "kernel/kptr_restrict", Level: "weak", Value: "0"}}}, // regression
	}
	alerts := Alerts(Diff(base, cur))
	kinds := map[string]bool{}
	for _, c := range alerts {
		kinds[c.Kind] = true
	}
	for _, want := range []string{"module-added", "taint-added", "mem-channel", "bpf-pinned", "hidden-module", "hardening-regression"} {
		if !kinds[want] {
			t.Errorf("missing alert %q; got %v", want, kinds)
		}
	}
}

func TestDiffQuietWhenUnchanged(t *testing.T) {
	s := Snapshot{Modules: []Module{{Name: "a"}}, Taint: TaintState{Flags: []string{"x"}}}
	if len(Alerts(Diff(s, s))) != 0 {
		t.Error("identical snapshots reported drift")
	}
}

func TestDiffRemovalIsInfoNotAlert(t *testing.T) {
	base := Snapshot{Modules: []Module{{Name: "a"}, {Name: "b"}}}
	cur := Snapshot{Modules: []Module{{Name: "a"}}}
	all := Diff(base, cur)
	if len(Alerts(all)) != 0 {
		t.Error("module removal should not be an alert")
	}
	found := false
	for _, c := range all {
		if c.Kind == "module-removed" {
			found = true
		}
	}
	if !found {
		t.Error("module removal not reported at info level")
	}
}

// ── BUG 1: a taint flag (or security taint bit) DISAPPEARING is drift ─────────

func TestDiffTaintRemovedIsAlert(t *testing.T) {
	base := Snapshot{Taint: TaintState{
		Raw:   12288, // O (12) + E (13)
		Flags: []string{"E: unsigned module loaded", "O: out-of-tree module loaded"},
	}}
	// "echo 0 > /proc/sys/kernel/tainted" as root clears both flags: the old
	// diff saw no difference at all because it only looked for NEW flags.
	cur := Snapshot{Taint: TaintState{Raw: 0}}
	alerts := Alerts(Diff(base, cur))
	if !diffKinds(alerts)["taint-removed"] {
		t.Fatalf("disappearing taint flag not reported; got %v", alerts)
	}
	if len(alerts) != 2 {
		t.Errorf("want one finding per cleared flag, got %v", alerts)
	}
}

func TestDiffTaintRawBitsClearedIsAlert(t *testing.T) {
	// A baseline whose flag list was written out lossily (or a bit beyond the
	// decode table) still has to compare raw masks.
	base := Snapshot{Taint: TaintState{Raw: 1 << 40}} // unknown high bit
	cur := Snapshot{Taint: TaintState{Raw: 0}}
	alerts := Alerts(Diff(base, cur))
	if !diffKinds(alerts)["taint-cleared"] {
		t.Errorf("cleared unknown taint bit not reported; got %v", alerts)
	}
	if !strings.Contains(alerts[0].Detail, "taint-bit-40") {
		t.Errorf("unknown bit not named: %v", alerts)
	}
}

func TestDiffTaintRawSecurityBitClearedIsAlert(t *testing.T) {
	// Security bits (E/O/F/R/D/K) cleared with no flag list on either side:
	// only the raw-mask comparison can see this.
	base := Snapshot{Taint: TaintState{Raw: 1 << 13}} // E: unsigned module
	cur := Snapshot{Taint: TaintState{Raw: 0}}
	alerts := Alerts(Diff(base, cur))
	if !diffKinds(alerts)["taint-cleared"] {
		t.Fatalf("cleared E bit not reported; got %v", alerts)
	}
	if !strings.Contains(alerts[0].Detail, "E: unsigned module loaded") {
		t.Errorf("cleared bit not named: %v", alerts)
	}
}

func TestDiffTaintAnyFlagDisappearingIsAlert(t *testing.T) {
	// Even a benign-looking flag (P proprietary, W warning) only ever
	// disappears because someone reset the taint word, which is itself the
	// anti-forensic act worth reporting.
	base := Snapshot{Taint: TaintState{Raw: 1<<10 | 1<<0, Flags: []string{"P: proprietary module loaded", "W: warning issued"}}}
	cur := Snapshot{Taint: TaintState{Raw: 0}}
	alerts := Alerts(Diff(base, cur))
	if len(alerts) != 2 {
		t.Errorf("want one alert per disappearing flag, got %v", alerts)
	}
}

func TestDiffTaintAddedStillAlert(t *testing.T) {
	base := Snapshot{Taint: TaintState{Raw: 0}}
	cur := Snapshot{Taint: TaintState{Raw: 8192, Flags: []string{"E: unsigned module loaded"}}}
	if !diffKinds(Alerts(Diff(base, cur)))["taint-added"] {
		t.Error("new taint flag not reported")
	}
}

// ── BUG 2: a module swapped in place under the same name ─────────────────────

func TestDiffModuleSwappedUnderSameNameIsAlert(t *testing.T) {
	base := Snapshot{Modules: []Module{
		{Name: "kmod", Size: 16384, RefCount: 1, UsedBy: []string{"nf_nat"}, Address: "0xffffffffc0000000"},
	}}
	cur := Snapshot{Modules: []Module{
		// unload + reload a different build under the same name
		{Name: "kmod", Size: 24576, RefCount: 1, UsedBy: []string{"nf_nat"}, Address: "0xffffffffc1000000"},
	}}
	alerts := Alerts(Diff(base, cur))
	kinds := diffKinds(alerts)
	if !kinds["module-changed"] {
		t.Fatalf("same-name module swap not reported; got %v", alerts)
	}
	if kinds["module-added"] || kinds["module-removed"] {
		t.Errorf("swap should not look like an add/remove: %v", alerts)
	}
}

func TestDiffModuleAddressOnlyChangeIsAlert(t *testing.T) {
	base := Snapshot{Modules: []Module{{Name: "kmod", Size: 16384, Address: "0xffffffffc0000000"}}}
	cur := Snapshot{Modules: []Module{{Name: "kmod", Size: 16384, Address: "0xffffffffc2000000"}}}
	if !diffKinds(Alerts(Diff(base, cur)))["module-changed"] {
		t.Errorf("address move not reported: %v", Diff(base, cur))
	}
}

func TestDiffModuleRefcountChurnIsInfoNotAlert(t *testing.T) {
	base := Snapshot{Modules: []Module{{Name: "kmod", Size: 16384, RefCount: 1, UsedBy: []string{"a"}, Address: "0x1"}}}
	cur := Snapshot{Modules: []Module{{Name: "kmod", Size: 16384, RefCount: 2, UsedBy: []string{"a", "b"}, Address: "0x1"}}}
	all := Diff(base, cur)
	if len(Alerts(all)) != 0 {
		t.Errorf("refcount/used-by churn alerted: %v", all)
	}
	if !diffKinds(all)["module-refs-changed"] {
		t.Errorf("refcount/used-by churn not reported at info level: %v", all)
	}
}

func TestDiffModuleRemovalStillInfo(t *testing.T) {
	base := Snapshot{Modules: []Module{{Name: "a", Size: 1, Address: "0x1"}, {Name: "b", Size: 1, Address: "0x2"}}}
	cur := Snapshot{Modules: []Module{{Name: "a", Size: 1, Address: "0x1"}}}
	all := Diff(base, cur)
	if len(Alerts(all)) != 0 {
		t.Errorf("module removal alerted: %v", all)
	}
	if !diffKinds(all)["module-removed"] {
		t.Errorf("module removal not reported at info level: %v", all)
	}
}

// ── BUG 3: hardening postures that regress undetected ────────────────────────

func TestDiffPostureNewlyPresentWeakIsAlert(t *testing.T) {
	// The baseline could not see the knob at all (no observation), so the old
	// ok->weak rule never fired even though the knob is weak now.
	base := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "kernel/kptr_restrict", Level: "ok", Value: "2"},
	}}}
	cur := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "kernel/kptr_restrict", Level: "ok", Value: "2"},
		{Key: "kernel/kexec_load_disabled", Level: "weak", Value: "0"},
	}}}
	alerts := Alerts(Diff(base, cur))
	if !diffKinds(alerts)["hardening-regression"] {
		t.Errorf("newly present weak knob not reported: %v", alerts)
	}
}

func TestDiffPostureLockdownUnknownThenWeakIsAlert(t *testing.T) {
	// Baseline: lockdown unreadable (level unknown). Now it reads "none".
	base := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "lockdown", Value: "", Level: "unknown"},
	}}}
	cur := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "lockdown", Value: "none", Level: "weak"},
	}}}
	if !diffKinds(Alerts(Diff(base, cur)))["hardening-regression"] {
		t.Errorf("lockdown regression after unreadable baseline not reported: %v", Diff(base, cur))
	}
}

func TestDiffPostureWeakGetsWeakerIsAlert(t *testing.T) {
	base := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "kernel/perf_event_paranoid", Level: "weak", Value: "1"},
	}}}
	cur := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "kernel/perf_event_paranoid", Level: "weak", Value: "-1"},
	}}}
	if !diffKinds(Alerts(Diff(base, cur)))["hardening-regression"] {
		t.Errorf("weak->weaker not reported: %v", Diff(base, cur))
	}
}

func TestDiffPostureNoChangeIsQuiet(t *testing.T) {
	s := Snapshot{Posture: Posture{Observations: []PostureNote{
		{Key: "kernel/kptr_restrict", Level: "ok", Value: "2"},
		{Key: "kernel/kexec_load_disabled", Level: "weak", Value: "0"},
		{Key: "lockdown", Level: "unknown"},
	}}}
	if len(Alerts(Diff(s, s))) != 0 {
		t.Errorf("unchanged posture reported drift: %v", Diff(s, s))
	}
}

func TestDiffPostureWeakerToOkIsQuiet(t *testing.T) {
	base := Snapshot{Posture: Posture{Observations: []PostureNote{{Key: "kernel/kptr_restrict", Level: "weak", Value: "0"}}}}
	cur := Snapshot{Posture: Posture{Observations: []PostureNote{{Key: "kernel/kptr_restrict", Level: "ok", Value: "2"}}}}
	if len(Diff(base, cur)) != 0 {
		t.Errorf("improvement reported as drift: %v", Diff(base, cur))
	}
}

// ── BUG 4: monitored inputs going unreadable must surface ────────────────────

func TestDiffNewSecurityWarningIsAlert(t *testing.T) {
	base := Snapshot{}
	cur := Snapshot{Warnings: []string{"proc/modules unreadable: permission denied"}}
	alerts := Alerts(Diff(base, cur))
	if !diffKinds(alerts)["input-unreadable"] {
		t.Fatalf("new /proc/modules warning not surfaced: %v", alerts)
	}
	for _, tc := range []string{
		"taint state unreadable: permission denied",
		"sys/module unreadable: permission denied",
		"proc/mounts: read aborted (line over 1048576 bytes), remainder of file not scanned",
		"sys/fs/bpf unreadable (bpffs not mounted?): permission denied",
		"TPM PCRs unreadable (no TPM, or unsupported bank)",
		"IMA measurement count unreadable (needs root, or IMA not enabled)",
	} {
		got := Diff(base, Snapshot{Warnings: []string{tc}})
		kinds := diffKinds(got)
		alerts := Alerts(got)
		if !kinds["input-unreadable"] {
			t.Errorf("warning %q not surfaced: %v", tc, got)
			continue
		}
		if len(alerts) == 0 {
			t.Errorf("warning %q should be an alert, got %v", tc, got)
		}
	}
	// The security-relevant list must not swallow unrelated warnings.
	if got := Diff(base, Snapshot{Warnings: []string{"kernel lockdown state unreadable"}}); len(Alerts(got)) != 0 {
		t.Errorf("unrelated warning escalated: %v", got)
	}
}

func TestDiffNewBenignWarningIsInfo(t *testing.T) {
	base := Snapshot{}
	cur := Snapshot{Warnings: []string{"kernel lockdown state unreadable (securityfs, or kernel built without lockdown)"}}
	all := Diff(base, cur)
	if len(Alerts(all)) != 0 {
		t.Errorf("benign warning escalated to alert: %v", all)
	}
	if !diffKinds(all)["input-unreadable"] {
		t.Errorf("new warning not reported at info level: %v", all)
	}
}

func TestDiffPreexistingWarningIsNotDrift(t *testing.T) {
	w := []string{"IMA measurement count unreadable (needs root, or IMA not enabled)"}
	s1 := Snapshot{Warnings: w}
	s2 := Snapshot{Warnings: w}
	if len(Diff(s1, s2)) != 0 {
		t.Errorf("warning present in both runs reported as drift: %v", Diff(s1, s2))
	}
	// Fewer warnings now (privilege granted) is not drift either.
	if len(Diff(Snapshot{Warnings: w}, Snapshot{})) != 0 {
		t.Errorf("disappearing warning reported as drift: %v", Diff(Snapshot{Warnings: w}, Snapshot{}))
	}
}
