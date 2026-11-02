package kstate

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureRoot builds a fake /proc + /sys tree and returns its root.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Two loaded modules; one used by another.
	write("proc/modules",
		"evil_rootkit 16384 0 - Live 0xffffffffc0a00000\n"+
			"nf_tables 299008 1 nf_nat, Live 0xffffffffc0800000\n")
	write("proc/sys/kernel/tainted", "0\n")
	write("proc/mounts", "none /sys/fs/bpf bpf rw,nosuid 0 0\nproc /proc proc rw 0 0\n")
	write("proc/sys/net/core/bpf_jit_harden", "1\n")
	write("proc/sys/kernel/unprivileged_bpf_disabled", "2\n")
	write("proc/sys/kernel/kptr_restrict", "2\n")
	write("proc/sys/kernel/yama/ptrace_scope", "1\n")
	write("sys/kernel/security/lockdown", "none [integrity] confidentiality\n")
	write("sys/kernel/security/lsm", "lockdown,capability,bpf,yama\n")
	// /sys/module: nf_tables is in /proc/modules; "sneaky" is NOT (hidden suspect).
	if err := os.MkdirAll(filepath.Join(root, "sys/module/nf_tables"), 0o755); err != nil {
		t.Fatal(err)
	}
	write("sys/module/nf_tables/initstate", "live\n")
	write("sys/module/sneaky/initstate", "live\n")
	// A kernel-memory channel present.
	write("dev/mem", "")
	write("proc/kcore", "")
	return root
}

func TestCollectModulesAndHidden(t *testing.T) {
	s := Collector{Root: fixtureRoot(t)}.Collect()
	if len(s.Modules) != 2 {
		t.Fatalf("modules = %d, want 2", len(s.Modules))
	}
	var nf *Module
	for i := range s.Modules {
		if s.Modules[i].Name == "nf_tables" {
			nf = &s.Modules[i]
		}
	}
	if nf == nil || nf.RefCount != 1 || len(nf.UsedBy) != 1 || nf.UsedBy[0] != "nf_nat" {
		t.Errorf("nf_tables parsed wrong: %+v", nf)
	}
	// "sneaky" is in /sys/module with initstate but not /proc/modules → suspect.
	if len(s.Hidden) != 1 || s.Hidden[0] != "sneaky" {
		t.Errorf("hidden suspects = %v, want [sneaky]", s.Hidden)
	}
}

func TestTaintDecode(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/sys/kernel"), 0o755)
	// bits: O (out-of-tree, 12) + E (unsigned, 13) = 0x3000 = 12288.
	os.WriteFile(filepath.Join(root, "proc/sys/kernel/tainted"), []byte("12288\n"), 0o644)
	ts := Collector{Root: root}.taint(&[]string{})
	if ts.Raw != 12288 {
		t.Fatalf("raw = %d", ts.Raw)
	}
	joined := ""
	for _, f := range ts.Flags {
		joined += f + ";"
	}
	if !contains(joined, "O:") || !contains(joined, "E:") {
		t.Errorf("taint flags missing O/E: %v", ts.Flags)
	}
}

func TestBPFAndMemAndPosture(t *testing.T) {
	s := Collector{Root: fixtureRoot(t)}.Collect()
	if len(s.BPF.FSMounts) != 1 || s.BPF.FSMounts[0] != "/sys/fs/bpf" {
		t.Errorf("bpffs mounts = %v", s.BPF.FSMounts)
	}
	if s.BPF.JITHarden == nil || *s.BPF.JITHarden != 1 {
		t.Errorf("jit_harden not read")
	}
	// mem channel /dev/mem present, /dev/kmem absent.
	present := map[string]bool{}
	for _, m := range s.MemChannels {
		present[m.Path] = m.Present
	}
	if !present["/dev/mem"] || present["/dev/kmem"] {
		t.Errorf("mem channels wrong: %+v", s.MemChannels)
	}
	if s.Posture.Lockdown != "integrity" {
		t.Errorf("lockdown = %q, want integrity", s.Posture.Lockdown)
	}
	// kptr_restrict=2 is ok; ptrace_scope=1 is ok.
	levels := map[string]string{}
	for _, o := range s.Posture.Observations {
		levels[o.Key] = o.Level
	}
	if levels["kernel/kptr_restrict"] != "ok" {
		t.Errorf("kptr_restrict level = %q", levels["kernel/kptr_restrict"])
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
