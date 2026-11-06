package enforce

import (
	"encoding/binary"
	"testing"
)

func rawEvent(reason uint32, family uint16, addr []byte) []byte {
	b := make([]byte, eventSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 7)
	le.PutUint32(b[4:], 7)
	le.PutUint32(b[8:], 1000)
	le.PutUint32(b[12:], reason)
	le.PutUint32(b[16:], 1)
	le.PutUint16(b[20:], family)
	binary.BigEndian.PutUint16(b[22:], 443)
	copy(b[24:], addr)
	copy(b[40:], "nc\x00")
	copy(b[56:], "sh\x00")
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
	v6 := make([]byte, 16)
	v6[15] = 1
	if e, err = DecodeEvent(rawEvent(3, 10, v6)); err != nil || e.Peer != "[::1]:443" || e.Reason != ReasonNetStdio {
		t.Fatalf("v6: %+v %v", e, err)
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
