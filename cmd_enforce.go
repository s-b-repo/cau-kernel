package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/s-b-repo/cau-kernel/internal/enforce"
)

// cmdEnforce drives the BPF-LSM enforcement guard. It works only in an eBPF
// build (`make enforce`); the default build reports that clearly.
//
//	cau-kernel enforce run [--core obj]   # resident: hold the LSM attachment (root)
//	cau-kernel enforce on|off             # freeze / release new execution
//	cau-kernel enforce status             # report the freeze state
//	cau-kernel enforce block|unblock PATH # per-inode blocklist (CO-RE enforcer only)
//	cau-kernel enforce blocked            # list blocked inodes
//	cau-kernel enforce killguard --obj O  # resident: protect listed PIDs from kill/ptrace
//	cau-kernel enforce protect|unprotect --pid N  # add/remove a protected PID
//	cau-kernel enforce protected          # list protected PIDs
//	cau-kernel enforce netshell           # resident: audit or refuse network shells at exec
//
// `run`/`killguard` hold the attachment; if the resident dies, enforcement
// lifts (fail-open) — a crash can never permanently brick the host.
//
// A BPF-LSM program can only be loaded on a kernel with CONFIG_BPF_LSM and `bpf`
// in /sys/kernel/security/lsm, as root. `make vm-test` boots the running kernel
// in QEMU to exercise the guards against the real verifier without host root.
func cmdEnforce(args []string, stdout, stderr io.Writer) int {
	if !enforce.Available {
		return failf(stderr, exitFailed, "%v", enforce.ErrUnavailable)
	}
	if len(args) < 1 {
		return failf(stderr, exitUsage, "usage: cau-kernel enforce run|on|off|status|block|unblock|blocked|killguard|protect|unprotect|protected|netshell")
	}
	switch args[0] {
	case "run":
		return enforceRun(args[1:], stdout, stderr)
	case "killguard":
		return enforceKillGuard(args[1:], stdout, stderr)
	case "netshell":
		return enforceNetshell(args[1:], stdout, stderr)
	case "protect", "unprotect":
		return enforceProtect(args[0] == "protect", args[1:], stdout, stderr)
	case "protected":
		pids, err := enforce.ListProtected()
		if err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		fmt.Fprintf(stdout, "protected pids (%d):\n", len(pids))
		for _, pid := range pids {
			fmt.Fprintf(stdout, "  %d\n", pid)
		}
		return exitOK
	case "on":
		return enforceSet(true, stdout, stderr)
	case "off":
		return enforceSet(false, stdout, stderr)
	case "status":
		frozen, err := enforce.StatusPinned()
		if err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		state := "allow (not frozen)"
		if frozen {
			state = "FROZEN (execve denied)"
		}
		fmt.Fprintf(stdout, "execution-freeze guard: %s\n", state)
		return exitOK
	case "block", "unblock":
		return enforceBlock(args[0] == "block", args[1:], stdout, stderr)
	case "blocked":
		inodes, err := enforce.ListBlocked()
		if err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		fmt.Fprintf(stdout, "blocked files (%d):\n", len(inodes))
		for _, f := range inodes {
			fmt.Fprintf(stdout, "  dev %d:%d inode %d\n", f.Dev>>20, f.Dev&0xfffff, f.Ino)
		}
		return exitOK
	default:
		return failf(stderr, exitUsage, "unknown enforce subcommand %q", args[0])
	}
}

func enforceRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enforce run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	core := fs.String("core", "", "path to the CO-RE object (lsm_fileopen.bpf.o) for per-inode policy; empty uses the embedded global-freeze guard")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g, err := enforce.Load(*core)
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	defer g.Close()
	mode := "global-freeze"
	if g.Core() {
		mode = "path-aware (per-inode blocklist + freeze)"
	}
	fmt.Fprintf(stdout, "[*] BPF-LSM guard attached: %s (state: allow). Control with `enforce on|off|block`; Ctrl-C to detach.\n", mode)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g.Wait(ctx)
	fmt.Fprintln(stdout, "\n[*] detaching guard (enforcement lifted)")
	return exitOK
}

// enforceNetshell holds the network-shell guard. It starts in audit so an
// operator sees what a policy would refuse before turning it on: deny refuses a
// legitimate inetd-style service as readily as a reverse shell.
func enforceNetshell(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enforce netshell", flag.ContinueOnError)
	fs.SetOutput(stderr)
	shell := fs.String("mode", "audit", "interpreters on network stdio: off, audit or deny (off leaves the any-program policy in charge)")
	any := fs.String("any-program", "audit", "every program on network stdio, interpreters included, which catches a renamed shell: off, audit or deny")
	memfd := fs.String("memfd", "audit", "execution from a memfd: off, audit or deny (deny breaks runc, which re-executes through one)")
	logPath := fs.String("log", "", "append events as JSON lines to this file (`cau ps --kernel-events` reads it)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	cfg, err := enforce.ParseNetshellConfig(*shell, *any, *memfd)
	if err != nil {
		return failf(stderr, exitUsage, "%v", err)
	}
	var log io.Writer
	var undecodable int
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return failf(stderr, exitFailed, "open event log: %v", err)
		}
		defer f.Close()
		log = f
	}
	g, err := enforce.LoadNetshell(cfg)
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	defer g.Close()
	fmt.Fprintf(stderr, "[*] network-shell guard attached (interpreters: %s, any program: %s, memfd: %s). Ctrl-C to detach.\n", *shell, *any, *memfd)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = g.Events(ctx, func(e enforce.Event) {
		line, jerr := json.Marshal(e)
		if jerr != nil {
			return
		}
		fmt.Fprintln(stdout, string(line))
		if log != nil {
			fmt.Fprintln(log, string(line))
		}
	}, func(derr error) {
		// A record the decoder cannot read is an event the operator would
		// never hear about. Say how many were lost, once, rather than
		// dropping them in silence.
		undecodable++
		if undecodable == 1 {
			fmt.Fprintf(stderr, "[WARN] an event could not be decoded and was dropped: %v\n", derr)
		}
	})
	fmt.Fprintln(stderr, "[*] detaching network-shell guard (policy lifted)")
	if undecodable > 1 {
		fmt.Fprintf(stderr, "[WARN] %d events could not be decoded and were dropped\n", undecodable)
	}
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	return exitOK
}

func enforceSet(on bool, stdout, stderr io.Writer) int {
	if err := enforce.SetPinned(on); err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	if on {
		fmt.Fprintln(stdout, "[+] execution frozen: new execve calls are denied until `enforce off`")
	} else {
		fmt.Fprintln(stdout, "[+] execution freeze cleared")
	}
	return exitOK
}

func enforceBlock(block bool, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		return failf(stderr, exitUsage, "usage: cau-kernel enforce %s <path>", map[bool]string{true: "block", false: "unblock"}[block])
	}
	path := args[0]
	fi, err := os.Stat(path)
	if err != nil {
		return failf(stderr, exitFailed, "stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return failf(stderr, exitFailed, "cannot read inode of %s on this platform", path)
	}
	key := enforce.BlockedFile{Ino: st.Ino, Dev: enforce.KernelDev(uint64(st.Dev))}
	if err := enforce.BlockInode(key, block); err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	verb := "blocked"
	if !block {
		verb = "unblocked"
	}
	fmt.Fprintf(stdout, "[+] %s inode %d on dev %d:%d (%s)\n", verb, st.Ino, key.Dev>>20, key.Dev&0xfffff, path)
	return exitOK
}

func enforceKillGuard(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enforce killguard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	obj := fs.String("obj", "bpf/lsm_killguard.bpf.o", "path to the CO-RE kill/ptrace object")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	g, err := enforce.LoadKillGuard(*obj)
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	defer g.Close()
	fmt.Fprintf(stdout, "[*] BPF-LSM kill/ptrace guard attached (no PID protected yet). "+
		"Add targets with `enforce protect --pid N`; Ctrl-C to detach (protection lifts).\n")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g.Wait(ctx)
	fmt.Fprintln(stdout, "\n[*] detaching kill/ptrace guard (protection lifted)")
	return exitOK
}

func enforceProtect(on bool, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enforce protect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pid := fs.Int("pid", 0, "thread-group id (PID) to protect/unprotect")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *pid <= 0 {
		return failf(stderr, exitUsage, "enforce %s requires --pid <n>", map[bool]string{true: "protect", false: "unprotect"}[on])
	}
	// Refuse to protect PID 1 or this control process: a protected enforcer
	// could not be torn down, which would defeat the fail-open safety model.
	if on && (*pid == 1 || *pid == os.Getpid()) {
		return failf(stderr, exitUsage, "refusing to protect pid %d (init or this process): that would break the fail-open recovery path", *pid)
	}
	if err := enforce.ProtectPID(uint32(*pid), on); err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	verb := "protected"
	if !on {
		verb = "unprotected"
	}
	fmt.Fprintf(stdout, "[+] %s pid %d from kill/ptrace\n", verb, *pid)
	return exitOK
}
