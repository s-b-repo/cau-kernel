package kstate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHookInventoryAndDrift(t *testing.T) {
	root := t.TempDir()
	c := Collector{Root: root}
	const trace = "sys/kernel/debug/tracing/enabled_functions"
	writeNode(t, root, "sys/kernel/debug/kprobes/list",
		"ffffffff81000000  k  vfs_read+0x0 [OPTIMIZED]\n"+
			"ffffffff81000010  r  vfs_write+0x4 [test_module] [DISABLED]\n")
	writeNode(t, root, trace, "kernel_read (2) R I D\n\tdirect-->bpf_prog_testing+0x0/0x20\n")
	writeNode(t, root, "sys/kernel/livepatch/example/enabled", "1\n")
	writeNode(t, root, "sys/kernel/livepatch/example/transition", "0\n")
	writeNode(t, root, "sys/kernel/security/lsm", "capability,yama,bpf\n")
	writeNode(t, root, "sys/module/module/parameters/sig_enforce", "Y\n")
	base := c.Collect()
	for _, table := range base.Hooks {
		if table.State != HookReadable {
			t.Errorf("%s state = %s (%s)", table.Kind, table.State, table.Issue)
		}
	}
	if !slices.Equal(base.Hooks[1].Entries, []string{"kernel_read (2) R I D direct-->bpf_prog_testing+0x0/0x20"}) ||
		base.Hooks[1].Source != "/"+trace {
		t.Fatalf("legacy ftrace entries = %+v", base.Hooks[1])
	}
	if !slices.Equal(base.Hooks[2].Entries, []string{"example enabled=1 transition=0"}) {
		t.Fatalf("livepatch entries = %+v", base.Hooks[2])
	}
	if !slices.Equal(base.Posture.LSM, []string{"capability", "yama", "bpf"}) {
		t.Fatalf("active LSMs = %v", base.Posture.LSM)
	}

	// Printed addresses can change while the symbolic registration stays put.
	writeNode(t, root, "sys/kernel/debug/kprobes/list",
		"123456789abcdef0 k vfs_read+0x0 [OPTIMIZED]\n"+
			"123456789abcdef1 r vfs_write+0x4 [test_module] [DISABLED]\n")
	if changes := Diff(base, c.Collect()); len(changes) != 0 {
		t.Fatalf("address-only change produced drift: %+v", changes)
	}

	writeNode(t, root, "sys/kernel/debug/kprobes/list",
		"123456789abcdef0 k vfs_read+0x0 [OPTIMIZED]\n"+
			"123456789abcdef0 k vfs_read+0x0 [OPTIMIZED]\n"+
			"123456789abcdef1 r vfs_write+0x4 [test_module] [DISABLED]\n")
	writeNode(t, root, "sys/kernel/livepatch/example/enabled", "0\n")
	writeNode(t, root, "sys/kernel/security/lsm", "capability,bpf,yama\n")
	writeNode(t, root, "sys/module/module/parameters/sig_enforce", "N\n")
	if err := os.Remove(filepath.Join(root, trace)); err != nil {
		t.Fatal(err)
	}
	results := Alerts(Diff(base, c.Collect()))
	for _, expected := range []struct{ kind, detail string }{
		{"hook-added", "kprobe 1 registration"},
		{"hook-added", "example enabled=0"},
		{"hook-removed", "example enabled=1"},
		{"hook-order-changed", "LSM registration order"},
		{"hook-coverage", "ftrace table is now unavailable"},
		{"hardening-regression", "module.sig_enforce"},
	} {
		if !slices.ContainsFunc(results, func(c Change) bool {
			return c.Kind == expected.kind && strings.Contains(c.Detail, expected.detail)
		}) {
			t.Errorf("missing %s (%s) in %+v", expected.kind, expected.detail, results)
		}
	}
}

func TestHookDriftUsesOnlyFullyObservedBaseline(t *testing.T) {
	root := t.TempDir()
	c := Collector{Root: root}
	const trace = "sys/kernel/tracing/enabled_functions"
	writeNode(t, root, trace, "kernel_read (1) R\nmalformed\n\tdirect-->dangling\n")
	partial := c.Collect()
	if got := partial.Hooks[1]; got.State != HookPartial ||
		!slices.Equal(got.Entries, []string{"kernel_read (1) R"}) || !strings.Contains(got.Issue, "2 malformed") {
		t.Fatalf("partial ftrace = %+v", got)
	}
	writeNode(t, root, trace, "")
	readable := c.Collect()
	if got := Alerts(Diff(partial, readable)); len(got) != 0 {
		t.Fatalf("unobserved baseline fabricated alerts: %+v", got)
	}
	if got := Alerts(Diff(readable, partial)); len(got) != 1 || got[0].Kind != "hook-coverage" {
		t.Fatalf("loss of table coverage did not alert: %+v", got)
	}

	legacy := readable
	legacy.Hooks = nil
	if got := Diff(legacy, readable); len(got) != 4 || len(Alerts(got)) != 0 {
		t.Fatalf("older signed snapshot must stay comparable with explicit coverage gaps: %+v", got)
	}
}

func TestPostureReportsKnobCoverageLoss(t *testing.T) {
	root := fixtureRoot(t)
	c := Collector{Root: root}
	base := c.Collect()
	writeNode(t, root, "proc/sys/kernel/kptr_restrict", "unknown\n")
	current := c.Collect()
	if !slices.ContainsFunc(current.Posture.Observations, func(o PostureNote) bool {
		return o.Key == "kernel/kptr_restrict" && o.Level == "unknown"
	}) {
		t.Fatalf("malformed sysctl was treated as known: %+v", current.Posture.Observations)
	}
	if !slices.ContainsFunc(Alerts(Diff(base, current)), func(c Change) bool {
		return c.Kind == "hardening-unreadable" && strings.Contains(c.Detail, "kernel/kptr_restrict")
	}) {
		t.Fatal("hardening coverage loss did not alert")
	}
}
