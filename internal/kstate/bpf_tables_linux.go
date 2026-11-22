//go:build linux && ebpf

package kstate

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const maxLiveBPFObjects = 4096

func liveBPFTables() []HookTable {
	programs, keys := liveBPFPrograms(ebpf.ProgramGetNextID, programIdentity, maxLiveBPFObjects)
	return []HookTable{programs, liveBPFLinks(keys)}
}

func liveBPFPrograms(next func(ebpf.ProgramID) (ebpf.ProgramID, error), identity func(ebpf.ProgramID) (string, error), limit int) (HookTable, map[ebpf.ProgramID]string) {
	table := HookTable{Kind: BPFProgramTable, Source: bpfProgramSource, State: HookReadable}
	keys := make(map[ebpf.ProgramID]string)
	var id ebpf.ProgramID
	var missing int
	for index := 0; ; index++ {
		following, err := next(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			bpfTableIssue(&table, err.Error())
			break
		}
		if index == limit || following <= id {
			bpfTableIssue(&table, "program enumeration exceeded its bounds")
			break
		}
		id = following
		key, err := identity(id)
		if err != nil {
			missing++
			continue
		}
		keys[id] = key
		table.Entries = append(table.Entries, key)
	}
	if missing > 0 {
		bpfTableIssue(&table, fmt.Sprintf("%d program records were unavailable", missing))
	}
	sort.Strings(table.Entries)
	return table, keys
}

func programIdentity(id ebpf.ProgramID) (string, error) {
	program, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", err
	}
	defer program.Close()
	// fdinfo reports the kernel's tag without requesting program instructions
	// or the contents of any mapped data.
	path := fmt.Sprintf("/proc/self/fdinfo/%d", program.FD())
	data, err := readBounded(path, 8<<10)
	if err != nil {
		return "", err
	}
	tag := ""
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, found := strings.Cut(line, ":"); found && key == "prog_tag" {
			tag = strings.TrimSpace(value)
			break
		}
	}
	if raw, err := hex.DecodeString(tag); err != nil || len(raw) != 8 {
		return "", errors.New("program tag missing or invalid")
	}
	return fmt.Sprintf("type=%s tag=%s", program.Type(), tag), nil
}

func liveBPFLinks(keys map[ebpf.ProgramID]string) HookTable {
	table := HookTable{Kind: BPFLinkTable, Source: bpfLinkSource, State: HookReadable}
	var iterator link.Iterator
	defer iterator.Close()
	var missing int
	for i := 0; iterator.Next(); i++ {
		if i == maxLiveBPFObjects {
			bpfTableIssue(&table, "link enumeration exceeded its bounds")
			break
		}
		info, err := iterator.Link.Info()
		if err != nil || keys[info.Program] == "" {
			missing++
			continue
		}
		entry := fmt.Sprintf("link_type=%d %s", info.Type, keys[info.Program])
		if trace := info.Tracing(); trace != nil {
			entry += fmt.Sprintf(" attach=%s", trace.AttachType)
		} else if cgroup := info.Cgroup(); cgroup != nil {
			entry += fmt.Sprintf(" attach=%s", cgroup.AttachType)
		}
		table.Entries = append(table.Entries, entry)
	}
	if err := iterator.Err(); err != nil {
		bpfTableIssue(&table, err.Error())
	}
	if missing > 0 {
		bpfTableIssue(&table, fmt.Sprintf("%d links lacked readable metadata or program identity", missing))
	}
	sort.Strings(table.Entries)
	return table
}

func bpfTableIssue(table *HookTable, issue string) {
	table.State = HookPartial
	if len(table.Entries) == 0 {
		table.State = HookUnavailable
	}
	if table.Issue != "" {
		table.Issue += "; "
	}
	table.Issue += issue
}
