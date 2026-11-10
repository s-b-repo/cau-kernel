package kstate

import (
	"sort"
	"strconv"
	"strings"
)

// SecurityRelevantWarnings fragments mark a snapshot warning that concerns an
// input whose loss mutes a security detector. If such an input becomes
// unreadable between the baseline and the current run the detector is being
// blinded, so the warning surfaces as an alert rather than as noise.
var securityRelevantWarnings = []string{
	"proc/modules",
	"sys/module",
	"proc/mounts",
	"sys/fs/bpf",
	"taint",
	"TPM PCRs",
	"IMA ",
}

// Change is one difference between a baseline Snapshot and a current one.
// Severity is "alert" for security-relevant drift (new module, module swapped
// in place, new taint, a taint bit disappearing, a newly-exposed memory channel,
// a hardening regression, a monitored input going unreadable) and "info"
// otherwise.
type Change struct {
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// Diff reports how current has drifted from baseline. The security-relevant
// cases — a module that appeared, a module swapped in place under the same name,
// a new taint flag, a security taint bit being cleared (the classic
// "echo 0 > /proc/sys/kernel/tainted" move), a newly-exposed memory channel, a
// hardening knob that weakened, a monitored input that went unreadable, a
// hidden-module suspect — are "alert"; disappearances and benign changes are
// "info".
func Diff(baseline, current Snapshot) []Change {
	var ch []Change

	// Modules: additions are the interesting case (a loaded rootkit) and a
	// same-name module whose Size/Address moved is a swap under the old name
	// (rootkit reload, DKMS rebuild). Removals are informational.
	base := moduleMap(baseline.Modules)
	cur := moduleMap(current.Modules)
	for name, m := range cur {
		b, ok := base[name]
		if !ok {
			ch = append(ch, Change{"module-added", "module loaded since baseline: " + name, "alert"})
			continue
		}
		if b.Size != m.Size || b.Address != m.Address {
			ch = append(ch, Change{"module-changed",
				"module " + name + " changed in place since baseline (size " +
					itoa(b.Size) + " -> " + itoa(m.Size) + ", address " +
					orNone(b.Address) + " -> " + orNone(m.Address) + ")", "alert"})
		}
		if !sameStringSet(b.UsedBy, m.UsedBy) {
			ch = append(ch, Change{"module-refs-changed",
				"module " + name + " used-by list changed since baseline", "info"})
		}
	}
	for name := range base {
		if _, ok := cur[name]; !ok {
			ch = append(ch, Change{"module-removed", "module unloaded since baseline: " + name, "info"})
		}
	}

	// Hidden-module suspects present now are always an alert.
	for _, h := range current.Hidden {
		ch = append(ch, Change{"hidden-module", "in /sys/module but not /proc/modules: " + h, "alert"})
	}

	ch = append(ch, diffTaint(baseline, current)...)

	// Memory channels newly present.
	basePresent := map[string]bool{}
	for _, m := range baseline.MemChannels {
		basePresent[m.Path] = m.Present
	}
	for _, m := range current.MemChannels {
		if m.Present && !basePresent[m.Path] {
			ch = append(ch, Change{"mem-channel", "kernel-memory channel newly present: " + m.Path, "alert"})
		}
	}

	// BPF pinned objects newly present.
	basePinned := stringSet(baseline.BPF.PinnedObjects)
	for _, p := range current.BPF.PinnedObjects {
		if !basePinned[p] {
			ch = append(ch, Change{"bpf-pinned", "new pinned eBPF object: " + p, "alert"})
		}
	}

	ch = append(ch, diffPosture(baseline, current)...)
	ch = append(ch, diffWarnings(baseline, current)...)

	sort.SliceStable(ch, func(i, j int) bool {
		if ch[i].Severity != ch[j].Severity {
			return ch[i].Severity == "alert" // alerts first
		}
		return ch[i].Kind < ch[j].Kind
	})
	return ch
}

// Alerts filters a Diff to the security-relevant changes.
func Alerts(changes []Change) []Change {
	var out []Change
	for _, c := range changes {
		if c.Severity == "alert" {
			out = append(out, c)
		}
	}
	return out
}

// diffTaint compares taint state in both directions. A flag that appeared is
// the obvious alert; a flag (or the raw bit behind it) that vanished is the
// evasion move — root can zero /proc/sys/kernel/tainted to clear E/O/F/K/D
// after loading an unsigned module — so it is an alert too.
func diffTaint(baseline, current Snapshot) []Change {
	var ch []Change
	baseTaint := stringSet(baseline.Taint.Flags)
	curTaint := stringSet(current.Taint.Flags)
	for _, fl := range current.Taint.Flags {
		if !baseTaint[fl] {
			ch = append(ch, Change{"taint-added", "new taint: " + fl, "alert"})
		}
	}
	reported := map[string]bool{}
	for _, fl := range baseline.Taint.Flags {
		if !curTaint[fl] {
			ch = append(ch, Change{"taint-removed", "taint flag disappeared since baseline: " + fl, "alert"})
			reported[fl] = true
		}
	}
	// Raw-mask comparison catches bits that never produced a flag: a bit the
	// decode table has no entry for, or one cleared while a flagless baseline
	// was written out. Security-relevant bits (E/O/F/R/D/K, unknown high bits)
	// cleared since the baseline are alerts.
	for i := uint(0); i < 64; i++ {
		bit := uint64(1) << i
		if baseline.Taint.Raw&bit == 0 || current.Taint.Raw&bit != 0 {
			continue
		}
		fl, sec := taintFlag(i)
		if !sec || reported[fl] {
			continue
		}
		reported[fl] = true
		ch = append(ch, Change{"taint-cleared",
			"security taint bit cleared since baseline (taint state reset?): " + fl, "alert"})
	}
	return ch
}

// diffPosture compares hardening posture. The baseline rule only caught an "ok"
// knob going "weak", which misses two ways to weaken a host: a knob that the
// baseline could not see at all and is weak now, and a knob that changed while
// already weak. Both are reported; unchanged, persistently weak state stays
// quiet so a permanently under-hardened host does not alert every run.
func diffPosture(baseline, current Snapshot) []Change {
	var ch []Change
	baseLevel := map[string]string{}
	baseValue := map[string]string{}
	for _, o := range baseline.Posture.Observations {
		baseLevel[o.Key] = o.Level
		baseValue[o.Key] = o.Value
	}
	for _, o := range current.Posture.Observations {
		if o.Level != "weak" {
			continue // only a weak posture is a finding; "ok"/"unknown" is not drift
		}
		was, known := baseLevel[o.Key]
		switch {
		case !known || was == "" || was == "unknown":
			// The knob was absent or unreadable at baseline: it is weak now
			// and that must not pass silently (fail closed).
			ch = append(ch, Change{"hardening-regression",
				o.Key + " is weak (" + o.Value + ") and was not measurable at baseline (" + o.Note + ")", "alert"})
		case was == "ok":
			ch = append(ch, Change{"hardening-regression", o.Key + " weakened to " + o.Value + " (" + o.Note + ")", "alert"})
		case was == "weak" && baseValue[o.Key] != o.Value:
			// Already weak and different: a further weakening, not a no-op.
			ch = append(ch, Change{"hardening-regression",
				o.Key + " changed while weak: " + baseValue[o.Key] + " -> " + o.Value + " (" + o.Note + ")", "alert"})
		}
	}
	return ch
}

// diffWarnings surfaces monitored inputs that became unreadable. A warning that
// was already there at baseline is not drift; a new one is at least info, and a
// security-relevant one is an alert — otherwise losing /proc/modules or the
// taint file between runs silently mutes the detector.
func diffWarnings(baseline, current Snapshot) []Change {
	var ch []Change
	baseWarn := stringSet(baseline.Warnings)
	for _, w := range current.Warnings {
		if baseWarn[w] {
			continue
		}
		ch = append(ch, Change{"input-unreadable",
			"monitored input became unreadable: " + w, warningSeverity(w)})
	}
	return ch
}

// warningSeverity rates a snapshot warning: security-relevant inputs lost are
// alerts, anything else information.
func warningSeverity(w string) string {
	for _, m := range securityRelevantWarnings {
		if strings.Contains(w, m) {
			return "alert"
		}
	}
	return "info"
}

// moduleMap keys a module list by name with the full record, so a same-name
// module can be compared field by field instead of only for presence.
func moduleMap(ms []Module) map[string]Module {
	m := make(map[string]Module, len(ms))
	for _, mod := range ms {
		m[mod.Name] = mod
	}
	return m
}

func stringSet(ss []string) map[string]bool {
	s := make(map[string]bool, len(ss))
	for _, v := range ss {
		s[v] = true
	}
	return s
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	bs := stringSet(b)
	for _, v := range a {
		if !bs[v] {
			return false
		}
	}
	return true
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
