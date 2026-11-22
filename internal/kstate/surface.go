package kstate

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ── eBPF surface ─────────────────────────────────────────────────────────────

func (c Collector) bpf(warn *[]string) BPFSurface {
	var s BPFSurface

	// bpffs mount points from /proc/mounts (type "bpf").
	if data, err := os.ReadFile(c.path("proc/mounts")); err == nil {
		for _, line := range scanLines("proc/mounts", data, warn) {
			f := strings.Fields(line)
			if len(f) >= 3 && f[2] == "bpf" {
				s.FSMounts = append(s.FSMounts, f[1])
			}
		}
	} else {
		warnf(warn, "proc/mounts unreadable: %v", err)
	}

	// Pinned maps/programs under the conventional bpffs root. Enumerating them
	// is the inventory; a pinned object not accounted for by a fleet policy is
	// what the console would alert on.
	walkRoot := c.path("sys/fs/bpf")
	if entries, err := os.ReadDir(walkRoot); err == nil {
		for _, e := range entries {
			s.PinnedObjects = append(s.PinnedObjects, filepath.Join("/sys/fs/bpf", e.Name()))
		}
		sort.Strings(s.PinnedObjects)
	} else {
		// A bpffs root that cannot be listed is a blind spot, not an empty one.
		warnf(warn, "sys/fs/bpf unreadable (bpffs not mounted?): %v", err)
	}

	s.JITEnabled = c.sysctlInt("proc/sys/net/core/bpf_jit_enable")
	s.JITHarden = c.sysctlInt("proc/sys/net/core/bpf_jit_harden")
	s.UnprivilegedDisabled = c.sysctlInt("proc/sys/kernel/unprivileged_bpf_disabled")
	return s
}

// ── kernel-memory access channels ────────────────────────────────────────────

func (c Collector) memChannels() []MemChannel {
	var out []MemChannel
	for _, p := range []string{"dev/mem", "dev/kmem", "proc/kcore", "dev/port"} {
		full := c.path(p)
		m := MemChannel{Path: "/" + p}
		if info, err := os.Lstat(full); err == nil {
			m.Present = true
			// String() keeps the node type, so /dev/mem renders "crw-rw----"
			// and not "rw-rw----": the device bit is the exposure signal.
			m.Mode = info.Mode().String()
		}
		out = append(out, m)
	}
	return out
}

// ── hardening posture ────────────────────────────────────────────────────────

// hardeningSysctls are the knobs the posture report reads, with the direction
// that is "hardened" and a one-line reason.
var hardeningSysctls = []struct {
	key     string // sysctl path under proc/sys
	minimum int    // threshold for the hardened state
	note    string
}{
	{"proc/sys/kernel/kptr_restrict", 1, "kernel pointer exposure via /proc"},
	{"proc/sys/kernel/dmesg_restrict", 1, "unprivileged dmesg (kernel log) access"},
	{"proc/sys/kernel/kexec_load_disabled", 1, "loading a new kernel over the running one"},
	{"proc/sys/kernel/modules_disabled", 1, "further module loading (one-way latch)"},
	{"proc/sys/kernel/unprivileged_bpf_disabled", 1, "unprivileged eBPF (big kernel attack surface)"},
	{"proc/sys/net/core/bpf_jit_harden", 1, "BPF JIT spraying hardening"},
	{"proc/sys/kernel/yama/ptrace_scope", 1, "cross-process ptrace (credential theft)"},
	{"proc/sys/kernel/perf_event_paranoid", 2, "perf_event_open exposure"},
}

func (c Collector) posture(warn *[]string, lsm HookTable) Posture {
	p := Posture{Sysctls: map[string]string{}, LSM: lsm.Entries, LSMState: lsm.State}

	// Lockdown is an observation whether or not it can be read: a baseline
	// taken where lockdown was unreadable must still be able to see a later
	// regression to "none", so the observation is emitted unconditionally with
	// level "unknown" when the node is absent or unprivileged.
	p.Lockdown = parseLockdown(c.readTrim("sys/kernel/security/lockdown"))
	if p.Lockdown == "" {
		warnf(warn, "kernel lockdown state unreadable (securityfs, or kernel built without lockdown)")
	}
	if _, err := os.Stat(c.path("sys/kernel/security/ima")); err == nil {
		p.IMA = true
	}

	for _, h := range hardeningSysctls {
		raw := c.readTrim(h.key)
		key := strings.TrimPrefix(h.key, "proc/sys/")
		level := "unknown"
		if value, err := strconv.Atoi(raw); err == nil {
			p.Sysctls[key] = raw
			level = "weak"
			if value >= h.minimum {
				level = "ok"
			}
		} else {
			raw = ""
		}
		p.Observations = append(p.Observations, PostureNote{
			Key: key, Value: raw, Level: level, Note: h.note,
		})
	}
	// Lockdown is an observation too.
	lvl := "ok"
	switch {
	case p.Lockdown == "":
		lvl = "unknown"
	case p.Lockdown == "none":
		lvl = "weak"
	}
	p.Observations = append(p.Observations, PostureNote{
		Key: "lockdown", Value: p.Lockdown, Level: lvl, Note: "kernel lockdown mode",
	})
	moduleSigning := PostureNote{
		Key: "module.sig_enforce", Level: "unknown", Note: "kernel module signature enforcement",
	}
	if data, err := readBounded(c.path("sys/module/module/parameters/sig_enforce"), 64); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "Y", "1":
			moduleSigning.Value, moduleSigning.Level = "Y", "ok"
		case "N", "0":
			moduleSigning.Value, moduleSigning.Level = "N", "weak"
		}
	}
	p.Observations = append(p.Observations, moduleSigning)
	return p
}

// ── small readers ────────────────────────────────────────────────────────────

func (c Collector) readTrim(rel string) string {
	data, err := os.ReadFile(c.path(rel))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c Collector) sysctlInt(rel string) *int {
	v := c.readTrim(rel)
	if v == "" {
		return nil
	}
	// A sysctl may read as the first token (e.g. bpf_jit_enable "1").
	fields := strings.Fields(v)
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	return &n
}

func parseLockdown(v string) string {
	// The file renders options with the active one in [brackets].
	if i := strings.Index(v, "["); i >= 0 {
		if j := strings.Index(v[i:], "]"); j > 0 {
			v = v[i+1 : i+j]
		}
	}
	switch v {
	case "none", "integrity", "confidentiality":
		return v
	default:
		return ""
	}
}
