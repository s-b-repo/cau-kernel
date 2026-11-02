package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cau-edr/cau-kernel/internal/enforce"
)

// cmdEnforce drives the BPF-LSM enforcement guard. It works only in an eBPF
// build (`make enforce`); the default build reports that clearly.
//
//	cau-kernel enforce run [--core obj]   # resident: hold the LSM attachment (root)
//	cau-kernel enforce on|off             # freeze / release new execution
//	cau-kernel enforce status             # report the freeze state
//	cau-kernel enforce block|unblock PATH # per-inode blocklist (CO-RE enforcer only)
//	cau-kernel enforce blocked            # list blocked inodes
//
// `run` holds the attachment; if it dies, enforcement lifts (fail-open).
func cmdEnforce(args []string, stdout, stderr io.Writer) int {
	if !enforce.Available {
		return failf(stderr, exitFailed, "%v", enforce.ErrUnavailable)
	}
	if len(args) < 1 {
		return failf(stderr, exitUsage, "usage: cau-kernel enforce run|on|off|status|block|unblock|blocked")
	}
	switch args[0] {
	case "run":
		return enforceRun(args[1:], stdout, stderr)
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
		fmt.Fprintf(stdout, "blocked inodes (%d):\n", len(inodes))
		for _, ino := range inodes {
			fmt.Fprintf(stdout, "  %d\n", ino)
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
	if err := enforce.BlockInode(st.Ino, block); err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	verb := "blocked"
	if !block {
		verb = "unblocked"
	}
	fmt.Fprintf(stdout, "[+] %s inode %d (%s)\n", verb, st.Ino, path)
	return exitOK
}
