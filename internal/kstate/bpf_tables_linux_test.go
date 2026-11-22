//go:build linux && ebpf

package kstate

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLiveBPFProgramCoverage(t *testing.T) {
	complete := func(id ebpf.ProgramID) (ebpf.ProgramID, error) {
		if id == 3 {
			return 0, os.ErrNotExist
		}
		return id + 1, nil
	}
	identify := func(id ebpf.ProgramID) (string, error) {
		if id == 2 {
			return "", errors.New("program disappeared")
		}
		return "type=LSM tag=0011223344556677", nil
	}
	got, keys := liveBPFPrograms(complete, identify, 3)
	if got.State != HookPartial || len(keys) != 2 || len(got.Entries) != 2 || got.Issue == "" {
		t.Fatalf("partial BPF table: %+v, %v", got, keys)
	}
	capped, _ := liveBPFPrograms(complete, identify, 1)
	if capped.State != HookPartial || len(capped.Entries) != 1 {
		t.Fatalf("capped BPF table: %+v", capped)
	}
	unavailable, _ := liveBPFPrograms(func(ebpf.ProgramID) (ebpf.ProgramID, error) {
		return 0, os.ErrPermission
	}, identify, 3)
	if unavailable.State != HookUnavailable || unavailable.Issue == "" {
		t.Fatalf("unavailable BPF table: %+v", unavailable)
	}
	empty, _ := liveBPFPrograms(func(ebpf.ProgramID) (ebpf.ProgramID, error) {
		return 0, os.ErrNotExist
	}, identify, 3)
	if empty.State != HookReadable || len(empty.Entries) != 0 {
		t.Fatalf("empty BPF table: %+v", empty)
	}
	for _, after := range []HookTable{got, unavailable} {
		changes := Diff(Snapshot{Hooks: []HookTable{empty}}, Snapshot{Hooks: []HookTable{after}})
		if !slices.ContainsFunc(changes, func(c Change) bool { return c.Kind == "hook-coverage" && c.Severity == "alert" }) {
			t.Fatalf("BPF visibility loss should alert: %+v", changes)
		}
	}
}
