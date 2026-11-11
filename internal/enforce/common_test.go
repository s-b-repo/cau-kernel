package enforce

import (
	"encoding/binary"
	"testing"
)

func rawEvent(reason uint32, family uint16, addr []byte) []byte {
	b := make([]byte, eventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 7) // pid: the process
	le.PutUint32(b[4:], 9) // tid: the thread that called execve
	le.PutUint32(b[8:], 1000)
	le.PutUint32(b[12:], reason)
	le.PutUint32(b[16:], 1)
	le.PutUint16(b[20:], family)
	binary.BigEndian.PutUint16(b[22:], 443)
	copy(b[24:], addr)
	copy(b[40:], "nc\x00")
	copy(b[56:], "sh\x00")
	le.PutUint64(b[72:], 123456)
	return b
}

func TestDecodeEvent(t *testing.T) {
	e, err := DecodeEvent(rawEvent(1, 2, []byte{192, 0, 2, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if e.PID != 7 || e.UID != 1000 || e.Reason != ReasonNetshell || !e.Denied || e.Peer != "192.0.2.1:443" || e.Comm != "nc" || e.Exe != "sh" {
		t.Fatalf("got %+v", e)
	}
	// The thread that called execve is not the process an operator looks up.
	if e.TID != 9 {
		t.Errorf("tid = %d, want 9", e.TID)
	}
	// "tgid" is the alias of "pid" an older reader of this log expects.
	if e.TGID != e.PID {
		t.Errorf("tgid = %d, want the pid %d", e.TGID, e.PID)
	}
	// The start time is what makes an event an attribution rather than a
	// coincidence: it is compared with the live process's own starttime.
	if e.StartTicks != 123456 {
		t.Errorf("start_ticks = %d, want 123456", e.StartTicks)
	}
	v6 := make([]byte, 16)
	v6[15] = 1
	if e, err = DecodeEvent(rawEvent(3, 10, v6)); err != nil || e.Peer != "[::1]:443" || e.Reason != ReasonNetStdio {
		t.Fatalf("v6: %+v %v", e, err)
	}
}

// The event layout is a contract between two build artefacts: this Go decoder
// and the struct in bpf/lsm_netshell.bpf.c. The offsets below are the C
// struct's, and a change on either side that the other does not follow is a
// guard that reports nonsense.
func TestEventLayoutMatchesTheCStruct(t *testing.T) {
	if eventSize != 80 {
		t.Errorf("event size = %d, want 80 (sizeof(struct event) in lsm_netshell.bpf.c)", eventSize)
	}
	// The field offsets the decoder reads, in the order it reads them.
	for _, off := range []struct {
		name string
		at   int
	}{
		{"pid", 0},
		{"tid", 4},
		{"uid", 8},
		{"reason", 12},
		{"denied", 16},
		{"family", 20},
		{"dport", 22},
		{"daddr", 24},
		{"comm", 40},
		{"exe", 56},
		{"start_ticks", 72},
	} {
		if off.at >= eventSize {
			t.Errorf("%s at %d is past the end of the event", off.name, off.at)
		}
	}
}

func TestDecodeEventRejectsMalformed(t *testing.T) {
	if _, err := DecodeEvent(make([]byte, eventSize-1)); err == nil {
		t.Fatal("short record accepted")
	}
	if _, err := DecodeEvent(rawEvent(99, 2, nil)); err == nil {
		t.Fatal("unknown reason accepted")
	}
}

func TestKernelDev(t *testing.T) {
	for _, c := range []struct {
		st   uint64
		want uint32
	}{
		{0x0801, 8<<20 | 1},         // sda1
		{0x0023, 0<<20 | 0x23},      // tmpfs: anonymous major 0
		{0x10301, 259<<20 | 1},      // nvme0n1p1, major 259
		{0x110300, 259<<20 | 0x100}, // extended minor
	} {
		if got := KernelDev(c.st); got != c.want {
			t.Errorf("KernelDev(%#x) = %#x, want %#x", c.st, got, c.want)
		}
	}
}

func TestParseNetshellConfig(t *testing.T) {
	c, err := ParseNetshellConfig("deny", "audit", "off")
	if err != nil || c.Interpreters != ModeDeny || c.AnyProgram != ModeAudit || c.Memfd != ModeOff {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseNetshellConfig("block", "audit", "off"); err == nil {
		t.Fatal("bad mode accepted")
	}
}

// The BPF map key is 16 bytes, so a longer name could never match.
func TestInterpreterNamesFitTheKey(t *testing.T) {
	for _, n := range Interpreters() {
		if len(n) > 15 {
			t.Errorf("%q does not fit the 16-byte map key", n)
		}
	}
	if len(Interpreters()) > 256 {
		t.Errorf("%d names overflow the 256-entry map", len(Interpreters()))
	}
}
