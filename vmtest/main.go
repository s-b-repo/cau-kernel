//go:build linux && ebpf

// Command vmtest is /init for the kernel test VM. It proves the guards against
// the real kernel: the verifier loads them, a real execve runs through the hook,
// and every benign case a guard must not break is exercised beside the attack it
// must stop. Run it with scripts/vm-test.sh, never on a host: it is PID 1.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/s-b-repo/cau-kernel/internal/enforce"
	"golang.org/x/sys/unix"
)

var failed, passed int

func check(name string, ok bool, detail string) {
	state := "ok  "
	if ok {
		passed++
	} else {
		failed++
		state = "FAIL"
	}
	fmt.Printf("VMTEST %s %s %s\n", state, name, detail)
}

func mounts() {
	for _, m := range []struct{ src, dst, fs string }{
		{"proc", "/proc", "proc"}, {"sys", "/sys", "sysfs"}, {"dev", "/dev", "devtmpfs"},
		{"bpf", "/sys/fs/bpf", "bpf"}, {"sec", "/sys/kernel/security", "securityfs"},
	} {
		_ = os.MkdirAll(m.dst, 0o755)
		if err := syscall.Mount(m.src, m.dst, m.fs, 0, ""); err != nil && err != syscall.EBUSY {
			fmt.Printf("VMTEST mount %s: %v\n", m.dst, err)
		}
	}
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	ifr.SetUint16(unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// tcpPair returns the accepted server side of a loopback connection as a file,
// the shape a bind shell inherits, and a closer.
func tcpPair() (*os.File, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		l.Close()
		return nil, nil, err
	}
	s, err := l.Accept()
	if err != nil {
		l.Close()
		c.Close()
		return nil, nil, err
	}
	f, err := s.(*net.TCPConn).File()
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close(); s.Close(); c.Close(); l.Close() }, nil
}

func unixPair() (*os.File, func(), error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	a, b := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	return a, func() { a.Close(); b.Close() }, nil
}

// run execs path with the given stdio and reports whether the kernel allowed it.
func run(path string, in, out *os.File) error {
	cmd := exec.Command(path)
	cmd.Stdin, cmd.Stdout = in, out
	return cmd.Run()
}

func denied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "operation not permitted")
}

type recorder struct {
	mu  sync.Mutex
	got []enforce.Event
}

func (r *recorder) add(e enforce.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, e)
}

// wait returns the first event with this reason, allowing for ring latency.
func (r *recorder) wait(reason string) (enforce.Event, bool) {
	for i := 0; i < 50; i++ {
		r.mu.Lock()
		for _, e := range r.got {
			if e.Reason == reason {
				r.mu.Unlock()
				return e, true
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return enforce.Event{}, false
}

func guarded(cfg enforce.NetshellConfig, fn func(r *recorder)) {
	g, err := enforce.LoadNetshell(cfg)
	if err != nil {
		check("load netshell guard", false, err.Error())
		return
	}
	r := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = g.Events(ctx, r.add, nil); close(done) }()
	fn(r)
	cancel()
	<-done
	_ = g.Close()
}

// startTicks reads field 22 of /proc/<pid>/stat: the process's start time in
// USER_HZ ticks, counted after the ')' that ends the comm field.
func startTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, fmt.Errorf("no comm terminator in stat line")
	}
	f := strings.Fields(string(b[i+1:]))
	const startTimeField = 19 // field 22 of the line; state, field 3, is index 0 here
	if len(f) <= startTimeField {
		return 0, fmt.Errorf("short stat line: %d fields", len(f))
	}
	n, err := strconv.ParseUint(f[startTimeField], 10, 64)
	return n, err
}

// identity proves the event says which process it happened to. The start time
// the guard records must be the number the live process's own /proc/<pid>/stat
// reports, in the same unit: that equality is the whole contract with
// `cau ps --kernel-events`, which matches an event to a process on it.
func identity(sock *os.File) {
	body, _ := os.ReadFile("/bin/plain")
	_ = os.MkdirAll("/tmp/ident", 0o755)
	if err := os.WriteFile("/tmp/ident/sleeper", body, 0o755); err != nil {
		check("identity: setup", false, err.Error())
		return
	}
	g, err := enforce.LoadNetshell(enforce.NetshellConfig{AnyProgram: enforce.ModeAudit})
	if err != nil {
		check("identity: load guard", false, err.Error())
		return
	}
	defer g.Close()
	r := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = g.Events(ctx, r.add, nil); close(done) }()

	cmd := exec.Command("/tmp/ident/sleeper")
	cmd.Stdin, cmd.Stdout = sock, sock
	if err := cmd.Start(); err != nil {
		check("identity: start", false, err.Error())
		cancel()
		<-done
		return
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	e, ok := r.wait(enforce.ReasonNetStdio)
	cancel()
	<-done

	ticks, terr := startTicks(cmd.Process.Pid)
	check("identity: the event names the process it saw", ok && e.PID == uint32(cmd.Process.Pid) && e.TID == uint32(cmd.Process.Pid),
		fmt.Sprintf("%+v pid=%d", e, cmd.Process.Pid))
	check("identity: the start time matches the live process", ok && terr == nil && e.StartTicks == ticks,
		fmt.Sprintf("event=%d live=%d err=%v", e.StartTicks, ticks, terr))
	check("identity: the event carries a time", ok && !e.Time.IsZero(), fmt.Sprintf("%v", e.Time))
}

func memfdExe() (string, func(), error) {
	body, err := os.ReadFile("/bin/plain")
	if err != nil {
		return "", nil, err
	}
	fd, err := unix.MemfdCreate("payload", 0)
	if err != nil {
		return "", nil, err
	}
	if _, err := unix.Write(fd, body); err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("/proc/self/fd/%d", fd), func() { unix.Close(fd) }, nil
}

func scenarios() {
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	fmt.Printf("VMTEST kernel lsm list: %s\n", lsm)

	sock, closeSock, err := tcpPair()
	if err != nil {
		check("loopback TCP", false, err.Error())
		return
	}
	defer closeSock()
	pipeR, pipeW, _ := os.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()
	us, closeUnix, err := unixPair()
	if err != nil {
		check("socketpair", false, err.Error())
		return
	}
	defer closeUnix()
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	lf, _ := listener.(*net.TCPListener).File()
	defer lf.Close()
	defer listener.Close()

	check("no guard: shell on TCP runs", run("/bin/sh", sock, sock) == nil, "")

	deny := enforce.NetshellConfig{Interpreters: enforce.ModeDeny, AnyProgram: enforce.ModeOff, Memfd: enforce.ModeOff}
	guarded(deny, func(r *recorder) {
		check("deny: shell on TCP is refused", denied(run("/bin/sh", sock, sock)), "")
		e, ok := r.wait(enforce.ReasonNetshell)
		check("deny: refusal is reported with the peer", ok && e.Denied && strings.HasPrefix(e.Peer, "127.0.0.1:") && e.Exe == "sh", fmt.Sprintf("%+v", e))
		check("deny: #! script on TCP is refused at its interpreter", denied(run("/bin/script.sh", sock, sock)), "")
		check("deny: non-interpreter on TCP still runs", run("/bin/plain", sock, sock) == nil, "")
		check("deny: shell on pipes still runs", run("/bin/sh", pipeR, pipeW) == nil, "")
		check("deny: shell on AF_UNIX socketpair still runs (ssh host cmd)", run("/bin/sh", us, us) == nil, "")
		check("deny: shell on a listening socket still runs (inetd Accept=no)", run("/bin/sh", lf, lf) == nil, "")
		check("deny: shell with only stdin on TCP still runs", run("/bin/sh", sock, pipeW) == nil, "")
		check("deny: shell with only stdout on TCP still runs", run("/bin/sh", pipeR, sock) == nil, "")
	})

	guarded(enforce.NetshellConfig{Interpreters: enforce.ModeAudit, AnyProgram: enforce.ModeAudit, Memfd: enforce.ModeOff}, func(r *recorder) {
		check("audit: shell on TCP runs", run("/bin/sh", sock, sock) == nil, "")
		e, ok := r.wait(enforce.ReasonNetshell)
		check("audit: event says it ran", ok && !e.Denied, fmt.Sprintf("%+v", e))
		check("audit: renamed shell on TCP runs", run("/tmp/x", sock, sock) == nil, "")
		e, ok = r.wait(enforce.ReasonNetStdio)
		check("audit: renamed shell is seen by the any-program policy", ok && e.Exe == "x", fmt.Sprintf("%+v", e))
	})

	guarded(enforce.NetshellConfig{AnyProgram: enforce.ModeDeny}, func(*recorder) {
		check("any-program deny: renamed shell on TCP is refused", denied(run("/tmp/x", sock, sock)), "")
		check("any-program deny: shell on TCP is refused without the name policy", denied(run("/bin/sh", sock, sock)), "")
		check("any-program deny: program on pipes still runs", run("/tmp/x", pipeR, pipeW) == nil, "")
	})

	exe, closeExe, err := memfdExe()
	if err != nil {
		check("memfd setup", false, err.Error())
		return
	}
	defer closeExe()
	guarded(enforce.NetshellConfig{Memfd: enforce.ModeAudit}, func(r *recorder) {
		check("memfd audit: runs", run(exe, pipeR, pipeW) == nil, "")
		e, ok := r.wait(enforce.ReasonMemfd)
		check("memfd audit: event names the memfd", ok && strings.HasPrefix(e.Exe, "memfd:"), fmt.Sprintf("%+v", e))
	})
	guarded(enforce.NetshellConfig{Memfd: enforce.ModeDeny}, func(*recorder) {
		check("memfd deny: refused", denied(run(exe, pipeR, pipeW)), "")
		check("memfd deny: ordinary program still runs", run("/bin/plain", pipeR, pipeW) == nil, "")
	})

	check("fail-open: detached guard leaves shell on TCP running", run("/bin/sh", sock, sock) == nil, "")

	identity(sock)
	eventLog(sock)
	blocklist()
	killGuard()

	g, err := enforce.Load("")
	if err != nil {
		check("load execution-freeze guard", false, err.Error())
		return
	}
	check("freeze: allow state runs", run("/bin/plain", pipeR, pipeW) == nil, "")
	if err := enforce.SetPinned(true); err != nil {
		check("freeze: set", false, err.Error())
	}
	check("freeze: on refuses every exec", denied(run("/bin/plain", pipeR, pipeW)), "")
	_ = enforce.SetPinned(false)
	check("freeze: off runs again", run("/bin/plain", pipeR, pipeW) == nil, "")
	_ = g.Close()
}

// blocklist proves the (device, inode) key: two fresh tmpfs mounts hand out the
// same inode numbers, so an inode-only key could not tell these files apart.
func blocklist() {
	var a, b unix.Stat_t
	for _, d := range []string{"/mnt/a", "/mnt/b"} {
		_ = os.MkdirAll(d, 0o755)
		if err := unix.Mount("tmpfs", d, "tmpfs", 0, ""); err != nil {
			check("mount "+d, false, err.Error())
			return
		}
		body, _ := os.ReadFile("/bin/plain")
		if err := os.WriteFile(d+"/implant", body, 0o755); err != nil {
			check("write "+d, false, err.Error())
			return
		}
	}
	_ = unix.Stat("/mnt/a/implant", &a)
	_ = unix.Stat("/mnt/b/implant", &b)
	check("blocklist: fixture has one inode number on two devices", a.Ino == b.Ino && a.Dev != b.Dev, fmt.Sprintf("ino %d/%d dev %d/%d", a.Ino, b.Ino, a.Dev, b.Dev))

	g, err := enforce.Load("/lsm_fileopen.bpf.o")
	if err != nil {
		check("load file guard", false, err.Error())
		return
	}
	defer g.Close()
	key := enforce.BlockedFile{Ino: a.Ino, Dev: enforce.KernelDev(a.Dev)}
	if err := enforce.BlockInode(key, true); err != nil {
		check("blocklist: add", false, err.Error())
		return
	}
	_, openErr := os.Open("/mnt/a/implant")
	check("blocklist: open is refused", openErr != nil && strings.Contains(openErr.Error(), "not permitted"), fmt.Sprint(openErr))
	check("blocklist: exec is refused", denied(run("/mnt/a/implant", nil, nil)), "")
	f, otherErr := os.Open("/mnt/b/implant")
	check("blocklist: same inode number on another device opens", otherErr == nil, fmt.Sprint(otherErr))
	if f != nil {
		f.Close()
	}
	check("blocklist: same inode number on another device runs", run("/mnt/b/implant", nil, nil) == nil, "")
	cliBlock()
	listed, err := enforce.ListBlocked()
	check("blocklist: listed", err == nil && len(listed) >= 1, fmt.Sprintf("%+v %v", listed, err))
	_ = enforce.BlockInode(key, false)
	check("blocklist: unblocked file runs", run("/mnt/a/implant", nil, nil) == nil, "")

	// A freeze stops execution. If it also stopped every open, nothing could run
	// `enforce off`, read a log or write one: the operator would be locked out.
	if err := enforce.SetPinned(true); err != nil {
		check("file guard freeze: set", false, err.Error())
		return
	}
	check("file guard freeze: exec is refused", denied(run("/bin/plain", nil, nil)), "")
	data, readErr := os.ReadFile("/bin/plain")
	check("file guard freeze: files stay readable", readErr == nil && len(data) > 0, fmt.Sprint(readErr))
	writeErr := os.WriteFile("/tmp/freeze-log", []byte("x"), 0o644)
	check("file guard freeze: files stay writable", writeErr == nil, fmt.Sprint(writeErr))
	check("file guard freeze: the operator can release it", enforce.SetPinned(false) == nil, "")
	check("file guard freeze: released", run("/bin/plain", nil, nil) == nil, "")
}

// eventLog runs the real command with a real policy. Its log is the contract with
// `cau ps --kernel-events`, so the line is printed for the host to read back.
func eventLog(sock *os.File) {
	const log = "/tmp/kernel-events.jsonl"
	cmd := exec.Command("/bin/cau-kernel", "enforce", "netshell", "--mode", "deny", "--log", log)
	if err := cmd.Start(); err != nil {
		check("cli: start guard", false, err.Error())
		return
	}
	var refused bool
	for i := 0; i < 100 && !refused; i++ { // attaching takes a moment
		refused = denied(run("/bin/sh", sock, sock))
		if !refused {
			time.Sleep(20 * time.Millisecond)
		}
	}
	check("cli: enforce netshell refuses a shell on TCP", refused, "")
	var line []byte
	for i := 0; i < 100 && len(line) == 0; i++ {
		line, _ = os.ReadFile(log)
		time.Sleep(10 * time.Millisecond)
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
	check("cli: event reached the log", len(line) > 0, "")
	fmt.Printf("VMTEST EVENTLOG %s\n", strings.SplitN(string(line), "\n", 2)[0])
	check("cli: stopping the guard lifts the policy", run("/bin/sh", sock, sock) == nil, "")
}

// cliBlock is what `cau ps --block-exe` does: the real binary refusing a running
// process's file, named only through /proc, with the file then unlinked as an
// implant would.
func cliBlock() {
	body, _ := os.ReadFile("/bin/plain")
	impl := "/mnt/a/sleeper"
	if err := os.WriteFile(impl, body, 0o755); err != nil {
		check("cli block: setup", false, err.Error())
		return
	}
	c := exec.Command(impl)
	if err := c.Start(); err != nil {
		check("cli block: start", false, err.Error())
		return
	}
	defer func() { _ = c.Process.Kill(); _ = c.Wait() }()
	out, err := exec.Command("/bin/cau-kernel", "enforce", "block", fmt.Sprintf("/proc/%d/exe", c.Process.Pid)).CombinedOutput()
	check("cli block: enforce block through /proc/<pid>/exe", err == nil, strings.TrimSpace(string(out)))
	check("cli block: the running implant's file no longer executes", denied(run(impl, nil, nil)), "")
	_ = os.Link(impl, impl+".again")
	check("cli block: another name for that file is refused too", denied(run(impl+".again", nil, nil)), "")
}

// sleeper starts a process that stays up to be signalled.
func sleeper(t string) *exec.Cmd {
	body, _ := os.ReadFile("/bin/plain")
	p := "/tmp/" + t + "/sleeper"
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, body, 0o755)
	c := exec.Command(p)
	if err := c.Start(); err != nil {
		check("kill guard: start "+t, false, err.Error())
		return nil
	}
	return c
}

func alive(c *exec.Cmd) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.Process.Pid))
	if err != nil {
		return false
	}
	return !strings.Contains(string(b), ") Z ")
}

// killGuard proves the sensor can be protected from a root attacker, that nothing
// else is, and that the protection cannot outlive the guard: an operator must
// always be able to take it away.
func killGuard() {
	g, err := enforce.LoadKillGuard("/lsm_killguard.bpf.o")
	if err != nil {
		check("kill guard: load through the verifier", false, err.Error())
		return
	}
	check("kill guard: load through the verifier", true, "")
	shielded, plain := sleeper("a"), sleeper("b")
	if shielded == nil || plain == nil {
		_ = g.Close()
		return
	}
	defer func() { _ = shielded.Process.Kill(); _ = shielded.Wait() }()
	defer func() { _ = plain.Process.Kill(); _ = plain.Wait() }()
	pid := shielded.Process.Pid
	if err := enforce.ProtectPID(uint32(pid), true); err != nil {
		check("kill guard: protect", false, err.Error())
		_ = g.Close()
		return
	}
	check("kill guard: root SIGKILL is refused", syscall.Kill(pid, syscall.SIGKILL) == syscall.EPERM, "")
	check("kill guard: root SIGTERM is refused", syscall.Kill(pid, syscall.SIGTERM) == syscall.EPERM, "")
	check("kill guard: root SIGSTOP is refused", syscall.Kill(pid, syscall.SIGSTOP) == syscall.EPERM, "")
	check("kill guard: ptrace attach is refused", unix.PtraceAttach(pid) == syscall.EPERM, "")
	time.Sleep(50 * time.Millisecond)
	check("kill guard: the protected process survived", alive(shielded), "")
	listed, err := enforce.ListProtected()
	check("kill guard: protected pid is listed", err == nil && len(listed) == 1 && int(listed[0]) == pid, fmt.Sprintf("%v %v", listed, err))

	self := os.Getpid()
	_ = enforce.ProtectPID(uint32(self), true)
	check("kill guard: a protected process may signal itself", syscall.Kill(self, 0) == nil, "")
	_ = enforce.ProtectPID(uint32(self), false)

	check("kill guard: an unprotected process still dies", syscall.Kill(plain.Process.Pid, syscall.SIGKILL) == nil, "")
	_ = enforce.ProtectPID(uint32(pid), false)
	check("kill guard: unprotect restores signals", syscall.Kill(pid, 0) == nil, "")
	_ = enforce.ProtectPID(uint32(pid), true)
	_ = g.Close()
	check("kill guard: fail-open, detaching lifts protection", syscall.Kill(pid, syscall.SIGKILL) == nil, "")
}

func powerOff() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	time.Sleep(time.Hour)
}

func main() {
	// Every copy of this binary in the image is the test payload except PID 1.
	if os.Getpid() != 1 {
		if filepath.Base(os.Args[0]) == "sleeper" {
			time.Sleep(time.Minute)
		}
		if filepath.Base(os.Args[0]) != "init" {
			os.Exit(0)
		}
	}
	defer powerOff()
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("VMTEST FAIL panic: %v\n", r)
		}
	}()
	mounts()
	if err := loopbackUp(); err != nil {
		check("bring up lo", false, err.Error())
		return
	}
	scenarios()
	fmt.Printf("VMTEST RESULT passed=%d failed=%d\n", passed, failed)
}
