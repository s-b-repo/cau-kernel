// Command cau-kernel is the kernel-integrity sensor for the CAU EDR program: it
// reads Linux kernel state (loaded modules and taint, the eBPF surface,
// kernel-memory access channels, hardening posture) from /proc and /sys and
// reports tamper- and rootkit-relevant drift against a signed baseline.
//
// It is the *detection* half of the plan's kernel work, done in userspace Go so
// it is portable and needs no kernel module. The active BPF-LSM *enforcement*
// (mediation/blocking) lives in bpf/ as a real eBPF-LSM program with its own
// load path; see bpf/README.md.
//
// Reference docs: the CAU engine repo (github.com/s-b-repo/cau), whose PLAN.md
// "Kernel-level support & anti-tamper" section this implements.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cau-edr/cau-kernel/internal/ksign"
	"github.com/cau-edr/cau-kernel/internal/kstate"
)

var version = "0.1.0-dev"

const (
	exitOK      = 0
	exitFinding = 1 // drift detected / posture weak (depending on command)
	exitFailed  = 3
	exitUsage   = 4
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprintf(w, `cau-kernel %s — kernel-integrity sensor (detection, userspace)

Usage:
  cau-kernel inventory [--root /] [--format text|json]   full kernel-state snapshot
  cau-kernel posture   [--root /] [--format text|json]   hardening posture report
  cau-kernel baseline  --out file [--root /] [--sign-key hex]   record a (signed) baseline
  cau-kernel drift     --baseline file [--root /] [--pubkey hex] [--all]   detect drift
  cau-kernel enforce   run|on|off|status    BPF-LSM execution-freeze guard (eBPF build, root)
  cau-kernel version

Drift exits 1 when a security-relevant change is found (a loaded module, a new
taint flag, a newly-exposed kernel-memory channel or pinned eBPF object, a
hardening regression, or a hidden-module suspect). Enforcement (BPF-LSM) is in
bpf/; this binary only observes.
`, version)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "inventory":
		return cmdInventory(args[1:], stdout, stderr)
	case "posture":
		return cmdPosture(args[1:], stdout, stderr)
	case "baseline":
		return cmdBaseline(args[1:], stdout, stderr)
	case "drift":
		return cmdDrift(args[1:], stdout, stderr)
	case "enforce":
		return cmdEnforce(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "cau-kernel %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func failf(stderr io.Writer, code int, format string, a ...any) int {
	fmt.Fprintf(stderr, "[ERROR] "+format+"\n", a...)
	return code
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ── inventory ────────────────────────────────────────────────────────────────

func cmdInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root to read kernel state from")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	snap := kstate.Collector{Root: *root}.Collect()
	if *format == "json" {
		if err := writeJSON(stdout, snap); err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		return exitOK
	}
	writeInventoryText(stdout, snap)
	return exitOK
}

// ── posture ──────────────────────────────────────────────────────────────────

func cmdPosture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	p := kstate.Collector{Root: *root}.Collect().Posture
	if *format == "json" {
		if err := writeJSON(stdout, p); err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		return exitOK
	}
	fmt.Fprintf(stdout, "Lockdown: %s\nLSM: %v\nIMA present: %v\n\n", orDash(p.Lockdown), p.LSM, p.IMA)
	for _, o := range p.Observations {
		mark := "ok "
		if o.Level == "weak" {
			mark = "weak"
		}
		fmt.Fprintf(stdout, "  [%s] %-34s = %-8s  %s\n", mark, o.Key, o.Value, o.Note)
	}
	return exitOK
}

// ── baseline ─────────────────────────────────────────────────────────────────

func cmdBaseline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	out := fs.String("out", "", "baseline file to write")
	signKey := fs.String("sign-key", "", "Ed25519 private key file (hex) to sign the baseline")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" {
		return failf(stderr, exitUsage, "--out is required")
	}
	var priv ed25519.PrivateKey
	if *signKey != "" {
		data, err := os.ReadFile(*signKey)
		if err != nil {
			return failf(stderr, exitFailed, "reading signing key: %v", err)
		}
		if priv, err = ksign.ParsePrivateKey(data); err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
	}
	snap := kstate.Collector{Root: *root}.Collect()
	env, err := ksign.Wrap(snap, priv)
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	data, err := ksign.Marshal(env)
	if err != nil {
		return failf(stderr, exitFailed, "%v", err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return failf(stderr, exitFailed, "writing %s: %v", *out, err)
	}
	signed := ""
	if priv != nil {
		signed = " (signed)"
	}
	fmt.Fprintf(stdout, "[+] recorded kernel-state baseline to %s%s (%d modules)\n", *out, signed, len(snap.Modules))
	return exitOK
}

// ── drift ────────────────────────────────────────────────────────────────────

func cmdDrift(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	baseline := fs.String("baseline", "", "baseline file from `cau-kernel baseline`")
	pubKey := fs.String("pubkey", "", "Ed25519 public key file (hex) to require + verify the baseline signature")
	all := fs.Bool("all", false, "show info-level changes too, not just alerts")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *baseline == "" {
		return failf(stderr, exitUsage, "--baseline is required")
	}
	data, err := os.ReadFile(*baseline)
	if err != nil {
		return failf(stderr, exitFailed, "reading baseline: %v", err)
	}
	env, err := ksign.Unmarshal(data)
	if err != nil {
		return failf(stderr, exitFailed, "parsing baseline: %v", err)
	}
	var pub ed25519.PublicKey
	if *pubKey != "" {
		kd, rerr := os.ReadFile(*pubKey)
		if rerr != nil {
			return failf(stderr, exitFailed, "reading public key: %v", rerr)
		}
		if pub, err = ksign.ParsePublicKey(kd); err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
	}
	var base kstate.Snapshot
	if err := env.Open(&base, pub); err != nil {
		return failf(stderr, exitFinding, "baseline: %v", err) // a bad signature is a finding
	}
	if pub != nil {
		fmt.Fprintln(stdout, "[*] baseline signature verified")
	} else if env.Signature != "" {
		fmt.Fprintln(stderr, "[WARN] baseline is signed but no --pubkey given; signature not checked")
	}

	cur := kstate.Collector{Root: *root}.Collect()
	changes := kstate.Diff(base, cur)
	shown := changes
	if !*all {
		shown = kstate.Alerts(changes)
	}
	if len(shown) == 0 {
		fmt.Fprintln(stdout, "[*] no kernel-state drift")
		return exitOK
	}
	alerts := 0
	for _, c := range shown {
		fmt.Fprintf(stdout, "[%s] %-20s %s\n", c.Severity, c.Kind, c.Detail)
		if c.Severity == "alert" {
			alerts++
		}
	}
	if alerts > 0 {
		return exitFinding
	}
	return exitOK
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
