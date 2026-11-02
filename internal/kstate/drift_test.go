package kstate

import "testing"

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
