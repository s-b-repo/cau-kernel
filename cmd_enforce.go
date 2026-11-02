package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cau-edr/cau-kernel/internal/enforce"
)

// cmdEnforce drives the BPF-LSM execution-freeze guard. It works only in an
// eBPF build (`make enforce`); the default build reports that clearly.
//
//	cau-kernel enforce run       # resident: hold the LSM attachment (root)
//	cau-kernel enforce on|off    # freeze / release new execution (control)
//	cau-kernel enforce status    # report the current state
//
// `run` holds the attachment; if it dies, enforcement lifts (fail-open).
func cmdEnforce(args []string, stdout, stderr io.Writer) int {
	if !enforce.Available {
		return failf(stderr, exitFailed, "%v", enforce.ErrUnavailable)
	}
	if len(args) != 1 {
		return failf(stderr, exitUsage, "usage: cau-kernel enforce run|on|off|status")
	}
	switch args[0] {
	case "run":
		return enforceRun(stdout, stderr)
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
	default:
		return failf(stderr, exitUsage, "unknown enforce subcommand %q (run|on|off|status)", args[0])
	}
}

func enforceRun(stdout, stderr io.Writer) int {
	g, err := enforce.Load()
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	defer g.Close()
	fmt.Fprintln(stdout, "[*] BPF-LSM execution-freeze guard attached (state: allow). Control with `enforce on|off`; Ctrl-C to detach.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g.Wait(ctx)
	fmt.Fprintln(stdout, "\n[*] detaching guard (execution no longer frozen)")
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
