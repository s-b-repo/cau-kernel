package enforce

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ErrUnavailable is returned by the default (non-eBPF) build's enforcement
// operations, and is the message the CLI shows when enforcement was not
// compiled in. Declared here (untagged) so both builds share one definition.
var ErrUnavailable = errors.New("enforce: this binary was built without eBPF enforcement; rebuild with `make enforce` (needs clang + a BPF-LSM kernel), see bpf/README.md")

// BlockedFile is a key in the file blocklist, laid out like struct inode_key in
// lsm_fileopen.bpf.c. The device matters: inode numbers repeat across filesystems.
type BlockedFile struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// KernelDev converts a stat(2) device number to the kernel's internal dev_t, the
// value sb->s_dev holds: 12 bits of major above 20 bits of minor. The two
// encodings differ, so a stat value used as a key would never match.
func KernelDev(st uint64) uint32 {
	major := ((st >> 8) & 0xfff) | ((st >> 32) &^ 0xfff)
	minor := (st & 0xff) | ((st >> 12) &^ 0xff)
	return uint32(major<<20 | minor&0xfffff)
}

// Mode is what a guard policy does with a match.
type Mode uint32

// Policy modes, matching the enum in lsm_netshell.bpf.c.
const (
	ModeOff   Mode = 0
	ModeAudit Mode = 1
	ModeDeny  Mode = 2
)

// ParseMode reads a mode name.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "off":
		return ModeOff, nil
	case "audit":
		return ModeAudit, nil
	case "deny":
		return ModeDeny, nil
	}
	return ModeOff, fmt.Errorf("enforce: mode must be off, audit or deny, not %q", s)
}

// NetshellConfig is the guard's policy.
type NetshellConfig struct {
	// Interpreters is the policy for a known interpreter (a shell, python,
	// perl…) on network stdio. Off means this policy does not apply; the
	// any-program policy still does, so "off" here is not "the check is
	// off", it is "the interpreter rule is off".
	Interpreters Mode
	// AnyProgram is the policy for any program on network stdio, which is
	// what catches a renamed shell. It applies to interpreters too, so it
	// is the policy that refuses a shell when the interpreter policy is
	// off.
	AnyProgram Mode
	// Memfd is the policy for execution from a memfd.
	Memfd Mode
}

// ParseNetshellConfig reads the three policy flags.
func ParseNetshellConfig(interpreters, anyProgram, memfd string) (NetshellConfig, error) {
	var c NetshellConfig
	var err error
	if c.Interpreters, err = ParseMode(interpreters); err != nil {
		return c, err
	}
	if c.AnyProgram, err = ParseMode(anyProgram); err != nil {
		return c, err
	}
	if c.Memfd, err = ParseMode(memfd); err != nil {
		return c, err
	}
	return c, nil
}

// interpreterBase are the programs a remote operator drives over a socket. The
// map is keyed on the exact file name, so versioned names are generated.
var interpreterBase = []string{
	"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "csh", "tcsh", "busybox", "rbash",
	"python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nodejs", "tclsh", "awk", "gawk", "mawk",
}

// Interpreters returns the names the guard treats as interpreters. It is not a
// security boundary on its own: a renamed copy is what the any-program policy
// is for.
func Interpreters() []string {
	out := append([]string(nil), interpreterBase...)
	for minor := 0; minor <= 20; minor++ {
		out = append(out, fmt.Sprintf("python3.%d", minor), fmt.Sprintf("php8.%d", minor), fmt.Sprintf("perl5.%d", 30+minor))
		out = append(out, fmt.Sprintf("lua5.%d", minor), fmt.Sprintf("ruby3.%d", minor))
	}
	return out
}

// Reasons an event was raised, matching the enum in lsm_netshell.bpf.c.
const (
	ReasonNetshell = "netshell"
	ReasonMemfd    = "memfd-exec"
	ReasonNetStdio = "network-stdio"
)

// Event is one exec the guard saw. Field names are the JSON-lines contract with
// `cau ps --kernel-events`.
type Event struct {
	// PID is the process (thread-group) id: what an operator looks up in
	// /proc. TID is the thread that called execve, which for a threaded
	// program is not the same thing.
	PID uint32 `json:"pid"`
	TID uint32 `json:"tid"`
	// TGID carries the same number as PID, under the name a reader of an
	// older log expects. It is an alias, not a second identifier: the
	// process id is one number, and a log written by this version is still
	// read correctly by an engine that predates the tid field.
	TGID   uint32 `json:"tgid"`
	UID    uint32 `json:"uid"`
	Reason string `json:"reason"`
	Denied bool   `json:"denied"`
	Peer   string `json:"peer,omitempty"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe"`
	// StartTicks is the process's start time in USER_HZ ticks — the same
	// clock and the same unit as field 22 of /proc/<pid>/stat. It is what
	// turns an event into an attribution: a PID alone is reused, and the
	// log outlives the processes it names, so an event that says which
	// process it happened to can be matched to that one and to no other.
	StartTicks uint64 `json:"start_ticks,omitempty"`
	// Time is when the guard read the event. The kernel has no wall clock
	// to give, and a reader wants to know how old a finding is.
	Time time.Time `json:"time,omitempty"`
}

// eventSize is sizeof(struct event) in lsm_netshell.bpf.c.
const eventSize = 4*5 + 2*2 + 16 + 16 + 16 + 8

// DecodeEvent parses one ring-buffer record. The record comes from the kernel,
// but its layout is a contract between two build artefacts, so it is checked.
func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("enforce: short event: %d bytes, want %d", len(raw), eventSize)
	}
	le := binary.LittleEndian
	e := Event{PID: le.Uint32(raw[0:]), TID: le.Uint32(raw[4:]), UID: le.Uint32(raw[8:]), Denied: le.Uint32(raw[16:]) != 0}
	e.TGID = e.PID
	switch le.Uint32(raw[12:]) {
	case 1:
		e.Reason = ReasonNetshell
	case 2:
		e.Reason = ReasonMemfd
	case 3:
		e.Reason = ReasonNetStdio
	default:
		return Event{}, fmt.Errorf("enforce: unknown event reason %d", le.Uint32(raw[12:]))
	}
	family := le.Uint16(raw[20:])
	port := binary.BigEndian.Uint16(raw[22:]) // skc_dport is network order
	addr := raw[24:40]
	switch family {
	case 2:
		e.Peer = net.JoinHostPort(net.IP(addr[:4]).String(), strconv.Itoa(int(port)))
	case 10:
		e.Peer = net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(int(port)))
	}
	e.Comm = cString(raw[40:56])
	e.Exe = cString(raw[56:72])
	e.StartTicks = le.Uint64(raw[72:])
	return e, nil
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
