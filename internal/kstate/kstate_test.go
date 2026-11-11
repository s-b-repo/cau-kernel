package kstate

import (
	"os"
	"path/filepath"
	"strings"
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

// ── BUG 5: a Scanner error must never be silent ───────────────────────────────

func TestCollectWarnsOnOversizedModulesLine(t *testing.T) {
	root := t.TempDir()
	big := strings.Repeat("A", maxScanLineBytes+1024) // one line past the limit
	writeNode(t, root, "proc/modules",
		"nf_tables 299008 1 nf_nat, Live 0xffffffffc0800000\n"+big+"\n"+
			"after 4096 0 - Live 0xffffffffc0a00000\n")
	s := Collector{Root: root}.Collect()
	found := false
	for _, w := range s.Warnings {
		if strings.Contains(w, "proc/modules") && strings.Contains(w, "aborted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("oversized /proc/modules line produced no warning: %v", s.Warnings)
	}
	// The first (valid) line is kept, the file after the abort is not scanned:
	// the gap is reported, not silently accepted.
	if len(s.Modules) != 1 || s.Modules[0].Name != "nf_tables" {
		t.Errorf("modules parsed wrong: %+v", s.Modules)
	}
}

func TestCollectReadsLongLineUnderLimit(t *testing.T) {
	// Realistic worst case: a line far past bufio's 64 KiB default but well
	// inside the raised buffer. The old default silently dropped the rest of
	// the file here.
	root := t.TempDir()
	long := strings.Repeat("x", 200*1024)
	writeNode(t, root, "proc/mounts",
		"none /sys/fs/bpf bpf rw,"+long+" 0 0\n"+
			"none /sys/fs/bpf2 bpf rw,nosuid 0 0\n")
	var warns []string
	b := Collector{Root: root}.bpf(&warns)
	if len(b.FSMounts) != 2 {
		t.Errorf("long line aborted the mount scan: %v", b.FSMounts)
	}
	for _, w := range warns {
		if strings.Contains(w, "proc/mounts") {
			t.Errorf("in-limit line produced a warning: %q", w)
		}
	}
}

func TestCollectWarnsOnOversizedMountsLine(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "proc/mounts",
		"none /sys/fs/bpf bpf rw 0 0\n"+strings.Repeat("B", maxScanLineBytes+64)+"\n")
	var warns []string
	Collector{Root: root}.bpf(&warns)
	found := false
	for _, w := range warns {
		if strings.Contains(w, "proc/mounts") && strings.Contains(w, "aborted") {
			found = true
		}
	}
	if !found {
		t.Errorf("oversized /proc/mounts line produced no warning: %v", warns)
	}
}

// ── BUG 8: Module.OutOfTree / Builtin must not always serialize false ─────────

// The kernel writes a /proc/modules line as
//
//	name size refcount used_by state address [taints]
//
// where the taints are the letters of the taint bits in parentheses ("(OE)")
// and "[permanent]," stands in the used-by field for a module that has an init
// but no exit: it can never be unloaded, so nothing can be using it either.
func TestModuleOutOfTreeAndBuiltinParsed(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "proc/modules",
		"unsigned_mod 16384 0 - Live 0xffffffffc0a00000 (OE)\n"+
			"clean_mod 8192 0 - Live 0xffffffffc0b00000\n"+
			"builtin_mod 1 0 [permanent], Live 0x0000000000000000\n"+
			"outoftree_only 4096 0 - Live 0xffffffffc0c00000 (O)\n"+
			"no_address 4096 0 - Live (O)\n"+
			"used_mod 4096 1 user_mod, Live 0xffffffffc0d00000\n")
	s := Collector{Root: root}.Collect()
	got := map[string]Module{}
	for _, m := range s.Modules {
		got[m.Name] = m
	}
	if !got["unsigned_mod"].OutOfTree {
		t.Errorf("out-of-tree module not marked out-of-tree: %+v", got["unsigned_mod"])
	}
	if got["clean_mod"].OutOfTree {
		t.Errorf("clean module marked out-of-tree: %+v", got["clean_mod"])
	}
	if !got["builtin_mod"].Builtin {
		t.Errorf("built-in not detected: %+v", got["builtin_mod"])
	}
	if len(got["builtin_mod"].UsedBy) != 0 {
		t.Errorf("a permanent module has a used-by list: %+v", got["builtin_mod"])
	}
	if got["builtin_mod"].OutOfTree {
		t.Errorf("built-in marked out-of-tree: %+v", got["builtin_mod"])
	}
	if got["clean_mod"].Address != "0xffffffffc0b00000" {
		t.Errorf("address lost for an untainted module: %+v", got["clean_mod"])
	}
	if !got["outoftree_only"].OutOfTree {
		t.Errorf("out-of-tree-only module not marked: %+v", got["outoftree_only"])
	}
	if !got["no_address"].OutOfTree {
		t.Errorf("taints column without an address not parsed: %+v", got["no_address"])
	}
	if got["unsigned_mod"].Taints == "" {
		t.Errorf("taints column not retained: %+v", got["unsigned_mod"])
	}
	if len(got["used_mod"].UsedBy) != 1 || got["used_mod"].UsedBy[0] != "user_mod" {
		t.Errorf("the used-by list is wrong: %+v", got["used_mod"])
	}
}

// ── BUG 1 (collector side): unknown taint bits must produce a flag ───────────

func TestTaintUnknownBitYieldsFallbackFlag(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "proc/sys/kernel/tainted", "1099511627776\n") // 1 << 40
	ts := Collector{Root: root}.taint(&[]string{})
	if len(ts.Flags) != 1 || !strings.Contains(ts.Flags[0], "taint-bit-40") {
		t.Errorf("unknown taint bit produced no flag: %+v", ts)
	}
}

// ── BUG 9: the device type must survive into the rendered mode ───────────────

func TestMemChannelModeKeepsDeviceType(t *testing.T) {
	root := t.TempDir()
	writeNode(t, root, "dev/mem", "")
	chans := (Collector{Root: root}).memChannels()
	var mem *MemChannel
	for i := range chans {
		if chans[i].Path == "/dev/mem" {
			mem = &chans[i]
		}
	}
	if mem == nil || !mem.Present {
		t.Fatalf("dev/mem not detected: %+v", chans)
	}
	// info.Mode().String() is 10 chars with a leading type bit; the old
	// Perm().String() dropped it and rendered "-rw-r--r--" as "rw-r--r--".
	if len(mem.Mode) != 10 || mem.Mode[0] != '-' {
		t.Errorf("mode %q does not carry the node type", mem.Mode)
	}
	// Where the test can create a real device node, the channel must show 'c'.
	if err := mknodChar(filepath.Join(root, "dev/kmem")); err == nil {
		chans = (Collector{Root: root}).memChannels()
		for _, m := range chans {
			if m.Path == "/dev/kmem" && !strings.HasPrefix(m.Mode, "c") {
				t.Errorf("device node rendered as %q, want a char device", m.Mode)
			}
		}
	} else {
		t.Logf("mknod unavailable in this environment; asserting the type bit only")
	}
}

func writeNode(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
