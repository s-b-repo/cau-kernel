//go:build linux && ebpf

package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The second `enforce run` must lose the race to pin the control channel
// before it can attach anything, so refusing to take over an existing pin is
// what keeps the control plane coherent.
func TestPinTakenRecognisesEexist(t *testing.T) {
	if !pinTaken(syscall.EEXIST) {
		t.Error("EEXIST not recognised as an existing pin")
	}
	if !pinTaken(&os.PathError{Op: "pin", Path: mapPinPath(), Err: syscall.EEXIST}) {
		t.Error("wrapped EEXIST not recognised")
	}
	if !pinTaken(syscall.ENOTEMPTY) {
		t.Error("ENOTEMPTY not recognised (a non-empty pin dir is also taken)")
	}
	if pinTaken(syscall.EACCES) {
		t.Error("EACCES is a real failure, not a taken pin")
	}
	if pinTaken(nil) {
		t.Error("nil error reported as a taken pin")
	}
}

func TestResidentBusyErrorNamesTheChannel(t *testing.T) {
	err := residentBusyError("enforcer", "control map", mapPinPath())
	want := "enforce: another enforcer is already resident (control map " + mapPinPath() + " is pinned); refusing to steal its control channel"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err, want)
	}

	err = residentBusyError("killguard", "protected-PID map", pidsMapPinPath())
	if !strings.Contains(err.Error(), "another killguard is already resident") ||
		!strings.Contains(err.Error(), pidsMapPinPath()) {
		t.Fatalf("killguard refusal did not name the resident and the pin: %v", err)
	}
}

func TestPinPathsAreUnderPinDir(t *testing.T) {
	for _, p := range []string{mapPinPath(), inodeMapPinPath(), pidsMapPinPath()} {
		if filepath.Dir(p) != pinDir {
			t.Errorf("%s is not under %s", p, pinDir)
		}
	}
}
