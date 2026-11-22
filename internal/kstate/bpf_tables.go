package kstate

// Live object views cover loaded programs and links whether pinned or not.
// IDs are local to an observation. Drift uses program type and the kernel's
// bytecode tag, and counts link types by associated program.
const (
	BPFProgramTable  = "bpf-program"
	BPFLinkTable     = "bpf-link"
	bpfProgramSource = "BPF_PROG_GET_NEXT_ID"
	bpfLinkSource    = "BPF_LINK_GET_NEXT_ID"
)
