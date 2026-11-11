package enforce

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The event record is written by the BPF program and read by this decoder.
// The two are separate build artefacts — a C struct and a Go struct — and
// nothing but this test keeps them in step: a field added on one side and not
// the other shifts every field after it, and the guard then reports a peer
// address as a process name.
//
// The contract is read out of the C source rather than restated here, so the
// test fails when the C struct changes and the Go side does not.

type cField struct {
	name  string
	size  int
	align int
}

var (
	cTypeSize = map[string]struct{ size, align int }{
		"__u8": {1, 1}, "char": {1, 1},
		"__u16": {2, 2}, "__s16": {2, 2},
		"__u32": {4, 4}, "__s32": {4, 4}, "int": {4, 4},
		"__u64": {8, 8}, "__s64": {8, 8},
	}
	cFieldRe = regexp.MustCompile(`^\s*(\w+)\s+(\w+)\s*(?:\[\s*(\d+)\s*\])?\s*$`)
)

func cEventFields(t *testing.T) []cField {
	t.Helper()
	src, err := os.ReadFile("../../bpf/lsm_netshell.bpf.c")
	if err != nil {
		t.Fatalf("read the BPF source: %v", err)
	}
	text := string(src)
	// Strip comments so a commented-out field is not read as one.
	text = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(text, " ")
	text = regexp.MustCompile(`//[^\n]*`).ReplaceAllString(text, " ")
	start := strings.Index(text, "struct event {")
	if start < 0 {
		t.Fatal("no struct event in lsm_netshell.bpf.c")
	}
	end := strings.Index(text[start:], "};")
	if end < 0 {
		t.Fatal("struct event is not closed in lsm_netshell.bpf.c")
	}
	body := text[start+len("struct event {") : start+end]

	var out []cField
	for _, decl := range strings.Split(body, ";") {
		decl = strings.TrimSpace(decl)
		if decl == "" {
			continue
		}
		m := cFieldRe.FindStringSubmatch(decl)
		if m == nil {
			t.Fatalf("cannot read the field declaration %q", decl)
		}
		ty, ok := cTypeSize[m[1]]
		if !ok {
			t.Fatalf("unknown C type %q in struct event", m[1])
		}
		f := cField{name: m[2], size: ty.size, align: ty.align}
		if m[3] != "" {
			n, err := strconv.Atoi(m[3])
			if err != nil {
				t.Fatalf("cannot read the array length in %q: %v", decl, err)
			}
			f.size *= n
		}
		out = append(out, f)
	}
	return out
}

func TestCEventStructMatchesTheDecoder(t *testing.T) {
	fields := cEventFields(t)
	if len(fields) == 0 {
		t.Fatal("the C struct event has no fields")
	}
	// The decoder's offsets, in the order it reads them.
	want := []string{"pid", "tid", "uid", "reason", "denied", "family", "dport", "daddr", "comm", "exe", "start_ticks"}
	if len(fields) != len(want) {
		t.Fatalf("the C struct has %d fields, the decoder reads %d: %v", len(fields), len(want), fields)
	}
	offset := 0
	for i, f := range fields {
		if f.name != want[i] {
			t.Errorf("field %d is %q in C, the decoder reads %q", i, f.name, want[i])
		}
		if offset%f.align != 0 {
			offset += f.align - offset%f.align
		}
		if f.name == "pid" && offset != 0 {
			t.Errorf("pid is at offset %d, the decoder reads it at 0", offset)
		}
		if f.name == "start_ticks" && offset != 72 {
			t.Errorf("start_ticks is at offset %d, the decoder reads it at 72", offset)
		}
		offset += f.size
	}
	if offset != eventSize {
		t.Errorf("the C struct is %d bytes, the decoder expects %d", offset, eventSize)
	}
}
