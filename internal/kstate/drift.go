package kstate

import "sort"

// Change is one difference between a baseline Snapshot and a current one.
// Severity is "alert" for security-relevant drift (new module, new taint, a new
// kernel-memory channel, a hardening regression) and "info" otherwise.
type Change struct {
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// Diff reports how current has drifted from baseline. The security-relevant
// cases — a module that appeared, a new taint flag, a newly-exposed memory
// channel, a hardening knob that weakened, a hidden-module suspect — are
// "alert"; disappearances and benign changes are "info".
func Diff(baseline, current Snapshot) []Change {
	var ch []Change

	// Modules: additions are the interesting case (a loaded rootkit); removals
	// are informational.
	base := moduleSet(baseline.Modules)
	cur := moduleSet(current.Modules)
	for name := range cur {
		if !base[name] {
			ch = append(ch, Change{"module-added", "module loaded since baseline: " + name, "alert"})
		}
	}
	for name := range base {
		if !cur[name] {
			ch = append(ch, Change{"module-removed", "module unloaded since baseline: " + name, "info"})
		}
	}

	// Hidden-module suspects present now are always an alert.
	for _, h := range current.Hidden {
		ch = append(ch, Change{"hidden-module", "in /sys/module but not /proc/modules: " + h, "alert"})
	}

	// Taint: any flag set now that was not set in the baseline.
	baseTaint := stringSet(baseline.Taint.Flags)
	for _, fl := range current.Taint.Flags {
		if !baseTaint[fl] {
			ch = append(ch, Change{"taint-added", "new taint: " + fl, "alert"})
		}
	}

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

	// Hardening regressions: an observation that was "ok" and is now "weak".
	baseLevel := map[string]string{}
	for _, o := range baseline.Posture.Observations {
		baseLevel[o.Key] = o.Level
	}
	for _, o := range current.Posture.Observations {
		if baseLevel[o.Key] == "ok" && o.Level == "weak" {
			ch = append(ch, Change{"hardening-regression", o.Key + " weakened to " + o.Value + " (" + o.Note + ")", "alert"})
		}
	}

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

func moduleSet(ms []Module) map[string]bool {
	s := make(map[string]bool, len(ms))
	for _, m := range ms {
		s[m.Name] = true
	}
	return s
}

func stringSet(ss []string) map[string]bool {
	s := make(map[string]bool, len(ss))
	for _, v := range ss {
		s[v] = true
	}
	return s
}
