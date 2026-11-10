package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/s-b-repo/cau-kernel/internal/ksign"
	"github.com/s-b-repo/cau-kernel/internal/kstate"
)

// cmdAttest records and verifies boot-anchored measurement: TPM PCRs, the IMA
// log summary, and kdump readiness. A PCR that changed since a (signed)
// baseline means the boot chain differs — the measured-boot tamper signal.
//
//	cau-kernel attest show                         # print current PCRs/IMA/kdump
//	cau-kernel attest baseline --out f [--sign-key] # record a (signed) baseline
//	cau-kernel attest verify   --baseline f [--pubkey] [--all]
func cmdAttest(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return failf(stderr, exitUsage, "usage: cau-kernel attest show|baseline|verify [flags]")
	}
	switch args[0] {
	case "show":
		return attestShow(args[1:], stdout, stderr)
	case "baseline":
		return attestBaseline(args[1:], stdout, stderr)
	case "verify":
		return attestVerify(args[1:], stdout, stderr)
	default:
		return failf(stderr, exitUsage, "unknown attest subcommand %q (show|baseline|verify)", args[0])
	}
}

func attestShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	m := kstate.Collector{Root: *root}.Measured()
	if *format == "json" {
		if err := writeJSON(stdout, m); err != nil {
			return failf(stderr, exitFailed, "%v", err)
		}
		return exitOK
	}
	fmt.Fprintf(stdout, "TPM PCR bank: %s (%d PCRs read)\n", orDash(m.PCRBank), len(m.PCRs))
	for _, idx := range sortedKeys(m.PCRs) {
		fmt.Fprintf(stdout, "  PCR %-2s %s\n", idx, m.PCRs[idx])
	}
	fmt.Fprintf(stdout, "IMA: count=%s violations=%s log-sha256=%s\n", intOrNA(m.IMACount), intOrNA(m.IMAViolations), orDash(m.IMALogSHA256))
	fmt.Fprintf(stdout, "kdump: crash-kernel-loaded=%v crash-size=%d bytes\n", m.Kdump.CrashKernelLoaded, m.Kdump.CrashSizeBytes)
	for _, w := range m.Warnings {
		fmt.Fprintf(stdout, "  [warn] %s\n", w)
	}
	return exitOK
}

func attestBaseline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest baseline", flag.ContinueOnError)
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
	m := kstate.Collector{Root: *root}.Measured()
	env, err := ksign.Wrap(m, priv)
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
	fmt.Fprintf(stdout, "[+] recorded measured-boot baseline to %s%s (%d PCRs)\n", *out, signed, len(m.PCRs))
	return exitOK
}

func attestVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "/", "filesystem root")
	baseline := fs.String("baseline", "", "baseline from `attest baseline`")
	pubKey := fs.String("pubkey", "", "Ed25519 public key file (hex) to require + verify the signature")
	all := fs.Bool("all", false, "show info-level changes too")
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
	var base kstate.Measured
	if err := env.Open(&base, pub); err != nil {
		return failf(stderr, exitFinding, "baseline: %v", err)
	}
	if pub != nil {
		fmt.Fprintln(stdout, "[*] baseline signature verified")
	} else if env.Signature != "" {
		fmt.Fprintln(stderr, "[WARN] baseline is signed but no --pubkey given; signature not checked")
	}
	cur := kstate.Collector{Root: *root}.Measured()
	changes := kstate.DiffMeasured(base, cur)
	shown := changes
	if !*all {
		shown = kstate.Alerts(changes)
	}
	if len(shown) == 0 {
		fmt.Fprintln(stdout, "[*] measured-boot state matches the baseline")
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

// sortedKeys returns PCR index keys in numeric order (0,1,2,...,23), not the
// lexical order that would interleave 1,10,11,2.
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		ni, ei := strconv.Atoi(ks[i])
		nj, ej := strconv.Atoi(ks[j])
		if ei == nil && ej == nil {
			return ni < nj
		}
		return ks[i] < ks[j]
	})
	return ks
}

func intOrNA(n int) string {
	if n < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d", n)
}
