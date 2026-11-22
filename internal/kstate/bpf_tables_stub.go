//go:build !linux || !ebpf

package kstate

func liveBPFTables() []HookTable {
	const issue = "live BPF objects require a Linux build with the ebpf tag"
	return []HookTable{
		{Kind: BPFProgramTable, Source: bpfProgramSource, State: HookUnavailable, Issue: issue},
		{Kind: BPFLinkTable, Source: bpfLinkSource, State: HookUnavailable, Issue: issue},
	}
}
