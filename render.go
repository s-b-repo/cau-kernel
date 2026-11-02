package main

import (
	"fmt"
	"io"

	"github.com/cau-edr/cau-kernel/internal/kstate"
)

func writeInventoryText(w io.Writer, s kstate.Snapshot) {
	fmt.Fprintf(w, "Kernel-state inventory\n======================\n\n")

	fmt.Fprintf(w, "Modules: %d loaded", len(s.Modules))
	if len(s.ModuleDirs) > 0 {
		fmt.Fprintf(w, "  (%d under /sys/module)", len(s.ModuleDirs))
	}
	fmt.Fprintln(w)
	if len(s.Hidden) > 0 {
		fmt.Fprintf(w, "  [ALERT] hidden-module suspects (in /sys/module, not /proc/modules): %v\n", s.Hidden)
	}

	fmt.Fprintf(w, "\nTaint: raw=%d\n", s.Taint.Raw)
	for _, f := range s.Taint.Flags {
		fmt.Fprintf(w, "  - %s\n", f)
	}
	if len(s.Taint.Flags) == 0 {
		fmt.Fprintln(w, "  (untainted)")
	}

	fmt.Fprintf(w, "\neBPF surface:\n")
	fmt.Fprintf(w, "  bpffs mounts   : %v\n", orNone(s.BPF.FSMounts))
	fmt.Fprintf(w, "  pinned objects : %v\n", orNone(s.BPF.PinnedObjects))
	fmt.Fprintf(w, "  jit_harden     : %s   unprivileged_bpf_disabled: %s\n", intPtr(s.BPF.JITHarden), intPtr(s.BPF.UnprivilegedDisabled))

	fmt.Fprintf(w, "\nKernel-memory channels:\n")
	for _, m := range s.MemChannels {
		state := "absent"
		if m.Present {
			state = "present " + m.Mode
		}
		fmt.Fprintf(w, "  %-12s %s\n", m.Path, state)
	}

	fmt.Fprintf(w, "\nHardening posture: lockdown=%s lsm=%v ima=%v\n", orDash(s.Posture.Lockdown), s.Posture.LSM, s.Posture.IMA)
	for _, o := range s.Posture.Observations {
		fmt.Fprintf(w, "  [%-4s] %-34s = %s\n", o.Level, o.Key, o.Value)
	}

	if len(s.Warnings) > 0 {
		fmt.Fprintf(w, "\nWarnings (needed more privilege or absent):\n")
		for _, warn := range s.Warnings {
			fmt.Fprintf(w, "  - %s\n", warn)
		}
	}
}

func orNone(ss []string) string {
	if len(ss) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%v", ss)
}

func intPtr(p *int) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *p)
}
