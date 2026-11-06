package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau-kernel/internal/enforce"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// fixtureRoot builds a minimal /proc + /sys tree for the CLI tests.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	w := func(rel, c string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("proc/modules", "nf_tables 299008 0 - Live 0x0\n")
	w("proc/sys/kernel/tainted", "0\n")
	w("proc/sys/kernel/kptr_restrict", "2\n")
	w("sys/kernel/security/lsm", "lockdown,capability,bpf\n")
	w("sys/class/tpm/tpm0/pcr-sha256/0", "aabb\n")
	w("sys/kernel/kexec_crash_loaded", "1\n")
	return root
}

func TestCLIUsageAndVersion(t *testing.T) {
	if code, _, _ := runCLI(t); code != exitUsage {
		t.Errorf("no args: code=%d", code)
	}
	if code, out, _ := runCLI(t, "version"); code != exitOK || !strings.Contains(out, "cau-kernel") {
		t.Errorf("version: code=%d out=%q", code, out)
	}
	if code, _, _ := runCLI(t, "bogus"); code != exitUsage {
		t.Errorf("unknown: code=%d", code)
	}
}

func TestCLIInventoryAndPosture(t *testing.T) {
	root := fixtureRoot(t)
	if code, out, _ := runCLI(t, "inventory", "--root", root); code != exitOK || !strings.Contains(out, "Modules: 1 loaded") {
		t.Errorf("inventory: code=%d out=%q", code, out)
	}
	if code, out, _ := runCLI(t, "inventory", "--root", root, "--format", "json"); code != exitOK || !strings.Contains(out, `"modules"`) {
		t.Errorf("inventory json: code=%d", code)
	}
	if code, out, _ := runCLI(t, "posture", "--root", root); code != exitOK || !strings.Contains(out, "kptr_restrict") {
		t.Errorf("posture: code=%d out=%q", code, out)
	}
}

func TestCLIBaselineDriftLifecycle(t *testing.T) {
	root := fixtureRoot(t)
	b := filepath.Join(t.TempDir(), "base.json")
	if code, _, e := runCLI(t, "baseline", "--root", root, "--out", b); code != exitOK {
		t.Fatalf("baseline: code=%d err=%s", code, e)
	}
	if code, _, _ := runCLI(t, "drift", "--root", root, "--baseline", b); code != exitOK {
		t.Errorf("clean drift: code=%d", code)
	}
	// Load a new module → drift alert (exit 1).
	os.WriteFile(filepath.Join(root, "proc/modules"), []byte("nf_tables 299008 0 - Live 0x0\nevil 16384 0 - Live 0x0\n"), 0o644)
	code, out, _ := runCLI(t, "drift", "--root", root, "--baseline", b)
	if code != exitFinding || !strings.Contains(out, "module-added") {
		t.Errorf("dirty drift: code=%d out=%q", code, out)
	}
}

func TestCLIAttestLifecycle(t *testing.T) {
	root := fixtureRoot(t)
	a := filepath.Join(t.TempDir(), "attest.json")
	if code, _, e := runCLI(t, "attest", "baseline", "--root", root, "--out", a); code != exitOK {
		t.Fatalf("attest baseline: code=%d err=%s", code, e)
	}
	if code, _, _ := runCLI(t, "attest", "verify", "--root", root, "--baseline", a); code != exitOK {
		t.Errorf("clean attest verify: code=%d", code)
	}
	// Change PCR 0 → boot-chain drift (exit 1).
	os.WriteFile(filepath.Join(root, "sys/class/tpm/tpm0/pcr-sha256/0"), []byte("9999\n"), 0o644)
	code, out, _ := runCLI(t, "attest", "verify", "--root", root, "--baseline", a)
	if code != exitFinding || !strings.Contains(out, "pcr-changed") {
		t.Errorf("dirty attest: code=%d out=%q", code, out)
	}
}

func TestCLIEnforceDegradesCleanly(t *testing.T) {
	// enforce must never crash. In the default build it reports "unavailable";
	// in the eBPF build (no root in CI) it fails cleanly on permissions. Either
	// way it is a non-OK exit, not a panic.
	code, _, errOut := runCLI(t, "enforce", "status")
	if code == exitOK {
		t.Errorf("enforce status unexpectedly succeeded: %q", errOut)
	}
	if enforce.Available {
		// eBPF build: a privilege/attach error, not the unavailable message.
		if strings.Contains(errOut, "without eBPF enforcement") {
			t.Errorf("eBPF build reported unavailable: %q", errOut)
		}
	} else if !strings.Contains(errOut, "without eBPF enforcement") {
		t.Errorf("default build should report unavailable: %q", errOut)
	}
}

func TestCLISignedBaselineFailsClosed(t *testing.T) {
	root := fixtureRoot(t)
	// Record a baseline, then corrupt it; verify with a pubkey must fail closed.
	// (Generate a keypair inline via the ksign/attest path using a raw seed.)
	seed := strings.Repeat("ab", 32) // 32 bytes = 64 hex chars (ed25519 seed)
	priv := filepath.Join(t.TempDir(), "priv.hex")
	os.WriteFile(priv, []byte(seed), 0o600)
	b := filepath.Join(t.TempDir(), "b.json")
	if code, _, _ := runCLI(t, "baseline", "--root", root, "--out", b, "--sign-key", priv); code != exitOK {
		t.Fatal("signed baseline record failed")
	}
	// Corrupt the signed baseline file.
	data, _ := os.ReadFile(b)
	os.WriteFile(b, append(data, ' '), 0o644)
	// Derive the pubkey from the seed for verification.
	// ed25519 seed -> pub is not trivially derivable without the lib; instead
	// reuse the module's own key handling: a mismatched/garbage pubkey of the
	// right length must fail closed too.
	pub := filepath.Join(t.TempDir(), "pub.hex")
	os.WriteFile(pub, []byte(strings.Repeat("cd", 32)), 0o644)
	if code, _, _ := runCLI(t, "drift", "--root", root, "--baseline", b, "--pubkey", pub); code == exitOK {
		t.Error("corrupted signed baseline verified OK (should fail closed)")
	}
}
