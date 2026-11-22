package kstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	HookReadable    = "readable"
	HookPartial     = "partial"
	HookUnavailable = "unavailable"

	maxHookTableBytes = 16 << 20
	maxLivepatchDirs  = 512
)

// HookTable describes one kernel-provided view of registered hooks. Entries
// from a partial table can be displayed but do not support drift comparison.
type HookTable struct {
	Kind    string   `json:"kind"`
	Source  string   `json:"source"`
	State   string   `json:"state"`
	Entries []string `json:"entries,omitempty"`
	Issue   string   `json:"issue,omitempty"`
}

func (c Collector) hooks(lsm HookTable) []HookTable {
	kprobes := c.readHookTable("kprobe", "sys/kernel/debug/kprobes/list", maxHookTableBytes, parseKprobes)
	ftrace := c.readHookTable("ftrace", "sys/kernel/tracing/enabled_functions", maxHookTableBytes, parseFtrace)
	if ftrace.State == HookUnavailable {
		// Older hosts may expose tracefs through debugfs.
		legacy := c.readHookTable("ftrace", "sys/kernel/debug/tracing/enabled_functions", maxHookTableBytes, parseFtrace)
		if legacy.State != HookUnavailable {
			ftrace = legacy
		}
	}
	return []HookTable{kprobes, ftrace, c.livepatches(), lsm}
}

func (c Collector) lsmHooks() HookTable {
	return c.readHookTable("lsm", "sys/kernel/security/lsm", 4096, parseLSM)
}

func (c Collector) readHookTable(kind, path string, limit int64, parse func([]byte) ([]string, error)) HookTable {
	t := HookTable{Kind: kind, Source: "/" + path}
	data, err := readBounded(c.path(path), limit)
	if err != nil {
		t.State, t.Issue = HookUnavailable, err.Error()
		return t
	}
	t.Entries, err = parse(data)
	t.State = HookReadable
	if err != nil {
		t.State, t.Issue = HookPartial, err.Error()
	}
	if kind != "lsm" {
		slices.Sort(t.Entries)
	}
	return t
}

func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular kernel file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read exceeded %d bytes", limit)
	}
	return data, nil
}

func parseKprobes(data []byte) ([]string, error) {
	var warnings, entries []string
	var malformed int
	for _, line := range scanLines("kprobe table", data, &warnings) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		isNullAddress := fields[0] == "(null)" || fields[0] == "(____ptrval____)"
		_, addrErr := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 64)
		if len(fields) < 3 || (addrErr != nil && !isNullAddress) || (fields[1] != "k" && fields[1] != "r") {
			malformed++
			continue
		}
		// The address column varies with KASLR and kernel pointer visibility.
		entries = append(entries, redactHookAddresses(strings.Join(fields[1:], " ")))
	}
	return entries, hookParseError(warnings, malformed)
}

func parseFtrace(data []byte) ([]string, error) {
	var warnings, entries []string
	var malformed int
	var pending string
	var hasContinuation bool
	for _, line := range scanLines("ftrace table", data, &warnings) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entry := redactHookAddresses(strings.Join(fields, " "))
		if strings.HasPrefix(fields[0], "direct-->") || strings.HasPrefix(fields[0], "direct(jmp)-->") {
			if pending == "" || hasContinuation {
				malformed++
				continue
			}
			pending += " " + entry
			hasContinuation = true
			continue
		}
		if pending != "" {
			entries = append(entries, pending)
			pending = ""
		}
		hasContinuation = false
		// The callback count follows the function and optional module name.
		countField := 1
		if len(fields) > 1 && strings.HasPrefix(fields[1], "[") && strings.HasSuffix(fields[1], "]") {
			countField++
		}
		if len(fields) <= countField {
			malformed++
			continue
		}
		countText, left := strings.CutPrefix(fields[countField], "(")
		countText, right := strings.CutSuffix(countText, ")")
		if _, err := strconv.ParseUint(countText, 10, 64); !left || !right || err != nil {
			malformed++
			continue
		}
		pending = entry
	}
	if pending != "" {
		entries = append(entries, pending)
	}
	return entries, hookParseError(warnings, malformed)
}

// Kernel symbols may contain offsets, and names such as bpf_prog_<tag> are
// useful identifiers. Redact only standalone addresses and unresolved pointers.
var hookAddress = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{8,16}\b|\(____ptrval____\)`)

func redactHookAddresses(s string) string {
	return hookAddress.ReplaceAllString(s, "<address>")
}

func hookParseError(warnings []string, malformed int) error {
	if malformed > 0 {
		warnings = append(warnings, fmt.Sprintf("%d malformed records", malformed))
	}
	if len(warnings) > 0 {
		return errors.New(strings.Join(warnings, "; "))
	}
	return nil
}

func parseLSM(data []byte) ([]string, error) {
	var entries []string
	seen := map[string]bool{}
	var malformed int
	for _, entry := range strings.Split(strings.TrimSpace(string(data)), ",") {
		name := strings.TrimSpace(entry)
		if name == "" || seen[name] || strings.ContainsFunc(name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
		}) {
			malformed++
			continue
		}
		seen[name] = true
		entries = append(entries, name)
	}
	return entries, hookParseError(nil, malformed)
}

func (c Collector) livepatches() HookTable {
	const path = "sys/kernel/livepatch"
	t := HookTable{Kind: "livepatch", Source: "/" + path, State: HookReadable}
	f, err := os.Open(c.path(path))
	if err != nil {
		t.State, t.Issue = HookUnavailable, err.Error()
		return t
	}
	defer f.Close()
	dirs, err := f.ReadDir(maxLivepatchDirs + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		t.State, t.Issue = HookUnavailable, err.Error()
		return t
	}
	if len(dirs) > maxLivepatchDirs {
		t.State, t.Issue = HookPartial, fmt.Sprintf("more than %d directory entries", maxLivepatchDirs)
		dirs = dirs[:maxLivepatchDirs]
	}
	var unreadable int
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		name := dir.Name()
		patchPath := c.path(filepath.Join(path, name))
		enabled, eErr := readBounded(filepath.Join(patchPath, "enabled"), 64)
		transition, tErr := readBounded(filepath.Join(patchPath, "transition"), 64)
		e := strings.TrimSpace(string(enabled))
		p := strings.TrimSpace(string(transition))
		if eErr != nil || tErr != nil || (e != "0" && e != "1") || (p != "0" && p != "1") {
			unreadable++
			continue
		}
		t.Entries = append(t.Entries, fmt.Sprintf("%s enabled=%s transition=%s", name, e, p))
	}
	if unreadable > 0 {
		t.State = HookPartial
		t.Issue = strings.TrimSpace(fmt.Sprintf("%s %d patches have unreadable state", t.Issue, unreadable))
	}
	slices.Sort(t.Entries)
	return t
}

func diffHooks(base, current []HookTable) []Change {
	stored := make(map[string]HookTable, len(base))
	for _, table := range base {
		stored[table.Kind] = table
	}
	var changes []Change
	for _, table := range current {
		previous := stored[table.Kind]
		switch {
		case previous.State == HookReadable && table.State != HookReadable:
			changes = append(changes, Change{"hook-coverage", table.Kind + " table is now " + table.State, "alert"})
		case previous.State != HookReadable || table.State != HookReadable:
			previousState := previous.State
			if previousState == "" {
				previousState = "not recorded"
			}
			detail := fmt.Sprintf("%s table could not be compared (baseline %s, current %s)", table.Kind, previousState, table.State)
			changes = append(changes, Change{"hook-coverage", detail, "info"})
		default:
			added := hookEntryChanges(table.Entries, previous.Entries)
			removed := hookEntryChanges(previous.Entries, table.Entries)
			if added != "" {
				changes = append(changes, Change{"hook-added", table.Kind + " " + added, "alert"})
			}
			if removed != "" {
				changes = append(changes, Change{"hook-removed", table.Kind + " " + removed, "alert"})
			}
			if table.Kind == "lsm" && added == "" && removed == "" && !slices.Equal(previous.Entries, table.Entries) {
				changes = append(changes, Change{"hook-order-changed", "active LSM registration order changed", "alert"})
			}
		}
	}
	return changes
}

func hookEntryChanges(from, other []string) string {
	counts := make(map[string]int, len(other))
	for _, entry := range other {
		counts[entry]++
	}
	const examplesLimit = 3
	var count int
	var examples []string
	for _, entry := range from {
		if counts[entry] > 0 {
			counts[entry]--
			continue
		}
		count++
		if len(examples) < examplesLimit {
			if len(entry) > 160 {
				entry = entry[:160] + "…"
			}
			examples = append(examples, strconv.Quote(entry))
		}
	}
	if count == 0 {
		return ""
	}
	return fmt.Sprintf("%d registration records (%s)", count, strings.Join(examples, ", "))
}
