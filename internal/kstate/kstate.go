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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

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
type Module struct {
	Name      string   `json:"name"`
	Size      int64    `json:"size"`
	RefCount  int      `json:"refcount"`
	UsedBy    []string `json:"used_by,omitempty"`
	State     string   `json:"state"` // Live, Loading, Unloading
	Address   string   `json:"address,omitempty"`
	OutOfTree bool     `json:"out_of_tree,omitempty"` // (O) taint on the module, when exposed
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
	Mode    string `json:"mode,omitempty"` // octal perms, when present
}

// Posture is the hardening posture as a report class — state, not scolding.
type Posture struct {
	Lockdown     string            `json:"lockdown,omitempty"` // none|integrity|confidentiality
	LSM          []string          `json:"lsm,omitempty"`
	IMA          bool              `json:"ima_present"`
	Sysctls      map[string]string `json:"sysctls,omitempty"`
	Observations []PostureNote     `json:"observations,omitempty"`
}

// PostureNote is one hardening observation. Level is "ok" or "weak"; the sensor
// reports the state and why it matters, and leaves the policy call to the
// operator (no "you must change this" nagging).
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
		*warn = append(*warn, "proc/modules unreadable: "+err.Error())
	} else {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 5 {
				continue
			}
			m := Module{Name: f[0], State: f[4]}
			m.Size, _ = strconv.ParseInt(f[1], 10, 64)
			m.RefCount, _ = strconv.Atoi(f[2])
			if f[3] != "-" {
				m.UsedBy = splitList(f[3])
			}
			if len(f) >= 6 {
				m.Address = f[5]
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
		*warn = append(*warn, "sys/module unreadable: "+derr.Error())
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

func (c Collector) taint(warn *[]string) TaintState {
	data, err := os.ReadFile(c.path("proc/sys/kernel/tainted"))
	if err != nil {
		*warn = append(*warn, "taint state unreadable: "+err.Error())
		return TaintState{}
	}
	raw, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	var sec, other []string
	for i, b := range taintBits {
		if raw&(1<<uint(i)) == 0 {
			continue
		}
		s := b.letter + ": " + b.note
		if b.sec {
			sec = append(sec, s)
		} else {
			other = append(other, s)
		}
	}
	return TaintState{Raw: raw, Flags: append(sec, other...)}
}

func splitList(s string) []string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ",")
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
