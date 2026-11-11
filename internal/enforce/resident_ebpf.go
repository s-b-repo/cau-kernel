//go:build linux && ebpf

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
)

// runDir is where the resident locks live. It is a runtime directory, like the
// pins themselves: both are gone when the host reboots.
const runDir = "/run/cau-kernel"

// residentLock is the lock a resident holds while it owns a pinned channel.
//
// The pin in bpffs is a filesystem entry, not a process resource: it outlives
// the resident that made it. A resident that was killed therefore leaves a pin
// behind, and the next resident is refused with "another enforcer is already
// resident" — so the documented recovery (stop the resident and everything
// lifts) restores the enforcement but not the ability to run the guard again,
// and the operator has to know to remove the pin by hand.
//
// The lock is the part a process owns: the kernel releases an advisory lock
// when the process dies, however it dies. A resident that finds a pin it
// cannot take over therefore knows the previous resident is gone, and the pin
// is stale.
type residentLock struct {
	file *os.File
}

// takeResidentLock takes the exclusive lock for a channel.
//
// It returns (nil, nil) when the lock is held by another resident, and also
// when the lock could not be set up at all (no runtime directory, no
// permission, a name that is a symlink). In every one of those cases the
// caller must not touch that channel's pin: a pin it cannot account for
// belongs to a resident that may be alive, and stealing it would let that
// resident's Close unlink the new owner's channel.
func takeResidentLock(channel string) (*residentLock, error) {
	dir := runDir
	if env := os.Getenv("CAU_KERNEL_RUN_DIR"); env != "" {
		dir = env
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil // audit:ok no lock directory: the caller keeps the old behaviour and refuses to steal a pin
	}
	path := filepath.Join(dir, channel+".lock")
	// The lock file is created exclusively and never followed through a
	// symlink: it is opened by name, and a name in a directory another
	// process can write is a name that can be pointed somewhere else.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, nil // audit:ok the lock cannot be created: the caller keeps the old behaviour and refuses to steal a pin
		}
		// A lock file from an earlier run: open it, still without
		// following a symlink.
		f, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, nil // audit:ok the lock cannot be opened: the caller keeps the old behaviour and refuses to steal a pin
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, nil // another resident holds the lock and is alive
	}
	// Record who holds it, so an operator can see which process to look at.
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	return &residentLock{file: f}, nil
}

// release gives the lock back. The kernel would release it when the process
// dies anyway; this is the orderly path.
func (l *residentLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

// pinChannel pins a map, taking over a pin that a dead resident left behind.
//
// A pin that is already there is stale when this process holds the channel's
// lock: no other resident is alive, so the pin belongs to one that died. It is
// removed and the map pinned in its place.
//
// Without the lock the pin is left alone and the refusal stands: stealing a
// pin a live resident depends on would let that resident's Close unlink the
// new owner's channel.
func pinChannel(m *ebpf.Map, path string, lock *residentLock) error {
	err := m.Pin(path)
	if err == nil {
		return nil
	}
	if !pinTaken(err) || lock == nil {
		return err
	}
	if rmErr := os.Remove(path); rmErr != nil {
		return err
	}
	return m.Pin(path)
}
