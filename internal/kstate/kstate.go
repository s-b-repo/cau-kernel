// Package kstate reads Linux kernel state relevant to tamper and rootkit
// detection — loaded modules and taint, the eBPF surface, kernel-memory access
// channels, and hardening posture — entirely from /proc and /sys. It is the
// detection half of the cau-kernel sensor: observe and report, never modify.
//
// Every reader takes a configurable Root so the collector can run against a
// fixture tree in tests and against "/" in production. A file that needs more
// privilege than the caller has is recorded as a Warning, never a fatal error:
// a sensor that aborts because one node was unreadable has told the attacker
// exactly how to blind it.
package kstate

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// maxScanLineBytes bounds a single line read by bufio.Scanner. The 64 KiB bufio
// default aborts a scan mid-file with no warning, which for /proc/modules means
// "the rest of the module list vanished" — exactly the silent gap this package
// is not allowed to have. 1 MiB is far beyond any realistic kernel line.
const maxScanLineBytes = 1 << 20

// scanLines splits a /proc-style file into lines, raising a warning naming the
// file when a line exceeds the limit (bufio.Scanner would otherwise stop
// mid-file and report nothing).
func scanLines(name string, data []byte, warn *[]string) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxScanLineBytes)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		warnf(warn, "%s: read aborted (line over %d bytes), remainder of file not scanned: %v",
			name, maxScanLineBytes, err)
	}
	return lines
}

// warnf appends a formatted warning to the snapshot's warning list.
func warnf(warn *[]string, format string, args ...any) {
	*warn = append(*warn, fmt.Sprintf(format, args...))
}

// Snapshot is a point-in-time view of the kernel state the sensor watches.
type Snapshot struct {
	Modules     []Module     `json:"modules"`
	ModuleDirs  []string     `json:"module_dirs"` // names under /sys/module (cross-view)
	Taint       TaintState   `json:"taint"`
	BPF         BPFSurface   `json:"bpf"`
	MemChannels []MemChannel `json:"mem_channels"`
	Posture     Posture      `json:"posture"`
	Hidden      []string     `json:"hidden_module_suspects,omitempty"`
	Warnings    []string     `json:"warnings,omitempty"`
}

// Module is one entry from /proc/modules.
//
// Address is the module's load address: a module reloaded at a different
// address under the same name (a rootkit swap) still carries the same Name but
// a different Address and usually a different Size — the diff uses both.
type Module struct {
	Name      string   `json:"name"`
	Size      int64    `json:"size"`
	RefCount  int      `json:"refcount"`
	UsedBy    []string `json:"used_by,omitempty"`
	State     string   `json:"state"` // Live, Loading, Unloading
	Address   string   `json:"address,omitempty"`
	Taints    string   `json:"taints,omitempty"`      // trailing taint letters from /proc/modules, when exposed
	OutOfTree bool     `json:"out_of_tree,omitempty"` // (O) taint on the module, when exposed
	Builtin   bool     `json:"builtin,omitempty"`     // [permanent] in /proc/modules
}

// TaintState decodes /proc/sys/kernel/tainted.
type TaintState struct {
	Raw   uint64   `json:"raw"`
	Flags []string `json:"flags,omitempty"` // human-readable, security-relevant first
}

// BPFSurface inventories the eBPF attack/monitoring surface.
type BPFSurface struct {
	FSMounts             []string `json:"bpffs_mounts,omitempty"`          // mount points of type bpf
	PinnedObjects        []string `json:"pinned_objects,omitempty"`        // paths under bpffs
	JITEnabled           *int     `json:"jit_enabled,omitempty"`           // net.core.bpf_jit_enable
	JITHarden            *int     `json:"jit_harden,omitempty"`            // net.core.bpf_jit_harden
	UnprivilegedDisabled *int     `json:"unprivileged_disabled,omitempty"` // kernel.unprivileged_bpf_disabled
}

// MemChannel is a kernel-memory access node and its exposure.
type MemChannel struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    string `json:"mode,omitempty"` // full mode bits, e.g. "crw-rw----" (/dev/mem is a char device)
}

// Posture is the hardening posture as a report class — state, not scolding.
type Posture struct {
	Lockdown     string            `json:"lockdown,omitempty"` // none|integrity|confidentiality
	LSM          []string          `json:"lsm,omitempty"`
	IMA          bool              `json:"ima_present"`
	Sysctls      map[string]string `json:"sysctls,omitempty"`
	Observations []PostureNote     `json:"observations,omitempty"`
}

// PostureNote is one hardening observation. Level is "ok", "weak", or
// "unknown" (the knob could not be read); the sensor reports the state and why
// it matters, and leaves the policy call to the operator (no "you must change
// this" nagging).
type PostureNote struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Level string `json:"level"`
	Note  string `json:"note"`
}

// Collector reads kernel state under Root (default "/").
type Collector struct {
	Root string
}

func (c Collector) root() string {
	if c.Root == "" {
		return "/"
	}
	return c.Root
}

func (c Collector) path(p string) string {
	return filepath.Join(c.root(), p)
}

// Collect gathers a full Snapshot, accumulating warnings for anything it could
// not read rather than failing.
func (c Collector) Collect() Snapshot {
	var s Snapshot
	s.Modules, s.ModuleDirs, s.Hidden = c.modules(&s.Warnings)
	s.Taint = c.taint(&s.Warnings)
	s.BPF = c.bpf(&s.Warnings)
	s.MemChannels = c.memChannels()
	s.Posture = c.posture(&s.Warnings)
	return s
}

// ── modules + taint ──────────────────────────────────────────────────────────

func (c Collector) modules(warn *[]string) (mods []Module, sysDirs []string, hidden []string) {
	data, err := os.ReadFile(c.path("proc/modules"))
	if err != nil {
		warnf(warn, "proc/modules unreadable: %v", err)
	} else {
		for _, line := range scanLines("proc/modules", data, warn) {
			f := strings.Fields(line)
			if len(f) < 5 {
				continue
			}
			m := Module{Name: f[0], State: f[4]}
			// Trailing fields after "name size refcount used_by state" are the
			// load address and, when the kernel exposes it, the module's own
			// taint letters ("(C,O)" / "O" / "[permanent]" for built-ins).
			for _, tok := range f[5:] {
				switch {
				case isAddressToken(tok):
					m.Address = tok
				case taintsTokenIsBuiltin(tok):
					m.Taints = tok
					m.Builtin = true
				case isTaintsToken(tok):
					m.Taints = tok
					m.OutOfTree = strings.ContainsAny(stripNonLetters(tok), "O")
				}
			}
			if n, perr := strconv.ParseInt(f[1], 10, 64); perr == nil {
				m.Size = n
			} else {
				warnf(warn, "proc/modules: unparseable size for %s (%q)", f[0], f[1])
			}
			if n, perr := strconv.Atoi(f[2]); perr == nil {
				m.RefCount = n
			} else {
				warnf(warn, "proc/modules: unparseable refcount for %s (%q)", f[0], f[2])
			}
			if f[3] != "-" {
				m.UsedBy = splitList(f[3])
			}
			mods = append(mods, m)
		}
	}
	// Cross-view: /sys/module lists every module the kernel knows, including
	// built-ins and some a /proc/modules-hiding rootkit may miss. A name in
	// /sys/module but absent from /proc/modules (and not built-in) is a
	// hidden-module suspect.
	entries, derr := os.ReadDir(c.path("sys/module"))
	if derr != nil {
		warnf(warn, "sys/module unreadable: %v", derr)
	}
	procSet := map[string]bool{}
	for _, m := range mods {
		procSet[m.Name] = true
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sysDirs = append(sysDirs, e.Name())
		// A module with a /sys/module/<name>/refcnt or /initstate is dynamically
		// loaded; if it is not in /proc/modules that is a reconciliation gap.
		if procSet[e.Name()] {
			continue
		}
		if _, statErr := os.Stat(c.path("sys/module/" + e.Name() + "/initstate")); statErr == nil {
			hidden = append(hidden, e.Name())
		}
	}
	sort.Strings(sysDirs)
	sort.Strings(hidden)
	return mods, sysDirs, hidden
}

// taintBits maps a taint bit position to (letter, security-relevant, meaning).
// The table is the canonical Linux taint list; a bit set beyond it (a future
// kernel taint, or a hand-crafted value written by an attacker) still has to be
// visible, so taintFlag falls back to "taint-bit-<n>" for unknown positions.
var taintBits = []struct {
	letter string
	sec    bool
	note   string
}{
	{"P", false, "proprietary module loaded"},
	{"F", true, "module force-loaded"},
	{"S", false, "SMP kernel on unsupported CPU"},
	{"R", true, "module force-unloaded"},
	{"M", false, "machine check"},
	{"B", false, "bad page referenced"},
	{"U", false, "user requested taint"},
	{"D", true, "kernel died recently (OOPS/BUG)"},
	{"A", false, "ACPI table overridden"},
	{"W", false, "warning issued"},
	{"C", false, "staging driver loaded"},
	{"I", false, "firmware workaround applied"},
	{"O", true, "out-of-tree module loaded"},
	{"E", true, "unsigned module loaded"},
	{"L", false, "soft lockup occurred"},
	{"K", true, "kernel live-patched"},
	{"X", false, "auxiliary taint"},
	{"T", false, "struct randomization plugin"},
	{"N", false, "in-kernel test run"},
}

// taintFlag renders bit i as a flag string, reporting whether it is
// security-relevant. Bits past the table are treated as security-relevant: an
// unknown bit appearing or disappearing must not pass silently.
func taintFlag(i uint) (string, bool) {
	if int(i) < len(taintBits) {
		b := taintBits[i]
		return b.letter + ": " + b.note, b.sec
	}
	return fmt.Sprintf("taint-bit-%d: unknown taint bit (no table entry)", i), true
}

func (c Collector) taint(warn *[]string) TaintState {
	data, err := os.ReadFile(c.path("proc/sys/kernel/tainted"))
	if err != nil {
		warnf(warn, "taint state unreadable: %v", err)
		return TaintState{}
	}
	raw, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if perr != nil {
		// Zero would read as a clean kernel: say the state is unknown instead.
		warnf(warn, "taint state unparseable: %v", perr)
		return TaintState{}
	}
	var sec, other []string
	for i := uint(0); i < 64; i++ {
		if raw&(1<<i) == 0 {
			continue
		}
		s, isSec := taintFlag(i)
		if isSec {
			sec = append(sec, s)
		} else {
			other = append(other, s)
		}
	}
	return TaintState{Raw: raw, Flags: append(sec, other...)}
}

// isAddressToken recognizes a kernel symbol address such as
// "0xffffffffc0a00000" (or the all-zero placeholder a built-in shows).
func isAddressToken(tok string) bool {
	return strings.HasPrefix(tok, "0x")
}

// isTaintsToken recognizes a /proc/modules trailing-taints field: a short
// letter/bracket token with no digits, e.g. "(C,O)", "O", "[permanent]".
func isTaintsToken(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if r >= '0' && r <= '9' {
			return false
		}
	}
	return true
}

func taintsTokenIsBuiltin(tok string) bool {
	return strings.Contains(strings.ToLower(tok), "permanent")
}

func stripNonLetters(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func splitList(s string) []string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ",")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
