//go:build linux && ebpf

// Package enforce loads and drives the BPF-LSM guard: a resident process holds
// the LSM attachment (lsm/bprm_check_security) and pins the control map to
// bpffs; a separate control invocation flips that pinned map to freeze or
// release new-process execution. Built only with `-tags ebpf`; the default
// binary carries a stub so it compiles and runs anywhere.
//
// Safety by design: the LSM attachment lives only as long as the resident
// process's link fd. If that process dies or is killed, the program detaches
// and execution is no longer frozen — a bug or crash can never permanently
// brick the host. Freezing is an explicit, supervised state.
//
// Attaching requires root (or CAP_BPF + CAP_MAC_ADMIN) and a kernel with
// BPF-LSM enabled (`bpf` in /sys/kernel/security/lsm).
package enforce

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Available reports whether this build has eBPF enforcement compiled in.
const Available = true

// lsm_guard.bpf.o is a BUILD ARTIFACT, not a checked-in source. The root
// Makefile's `bpf-object` target compiles it (clang -target bpf, from bpf/) and
// copies it into this package, and *.bpf.o is deliberately .gitignore'd. An
// `ebpf`-tagged build on a fresh clone therefore fails with
//
//	pattern lsm_guard.bpf.o: no matching files found
//
// so run `make bpf-object` (or `make enforce`, which depends on it) first.

//go:generate make -C ../.. bpf-object

//go:embed lsm_guard.bpf.o
var guardObject []byte

const (
	progName = "cau_exec_guard"
	mapName  = "cau_enforce"
	pinDir   = "/sys/fs/bpf/cau-kernel"
	// coreProgName / inodeMapName are in the CO-RE path-aware object.
	coreProgName = "cau_file_open"
	inodeMapName = "cau_blocked_inodes"
)

func mapPinPath() string      { return filepath.Join(pinDir, mapName) }
func inodeMapPinPath() string { return filepath.Join(pinDir, inodeMapName) }

// Guard is a loaded-and-attached resident guard. Hold it for the lifetime of
// the enforcer; Close detaches the program and removes the pinned maps this
// Load pinned (created), so a control-only or refused-to-start path never
// unlinks a pin another resident owns.
type Guard struct {
	coll    *ebpf.Collection
	lnk     link.Link
	core    bool
	created bool
}

// pinTaken reports whether a failed Pin means the bpffs entry already exists —
// the kernel returns EEXIST rather than letting a second process replace the
// pinned object, so the pin belongs to a process that is still running.
func pinTaken(err error) bool { return errors.Is(err, os.ErrExist) }

// residentBusyError is what a second resident attempt sees. Only one resident
// may own a pinned control channel: stealing it would let that resident's Close
// unlink the pin the running resident's `enforce on|off/status` depends on.
func residentBusyError(what, channel, path string) error {
	return fmt.Errorf("enforce: another %s is already resident (%s %s is pinned); refusing to steal its control channel", what, channel, path)
}

// removeCreatedPins unlinks only pins this process created; it never touches a
// pin owned by another resident.
func removeCreatedPins(control, inode bool) {
	if control {
		_ = os.Remove(mapPinPath())
	}
	if inode {
		_ = os.Remove(inodeMapPinPath())
	}
}

// Load attaches an execution-freeze guard and pins its control map to bpffs so
// a control CLI can reach it, starting in the ALLOW state. With corePath == ""
// it loads the embedded self-contained guard (global freeze only). With a
// corePath it loads the CO-RE path-aware object from that file, attaching
// lsm/file_open and also pinning the per-inode blocklist map. The caller runs
// the resident loop and Closes on exit.
func Load(corePath string) (*Guard, error) {
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return nil, fmt.Errorf("enforce: create bpffs pin dir %s (is bpffs mounted?): %w", pinDir, err)
	}
	prog := progName
	obj := guardObject
	core := corePath != ""
	if core {
		data, err := os.ReadFile(corePath)
		if err != nil {
			return nil, fmt.Errorf("enforce: read CO-RE object %s: %w", corePath, err)
		}
		obj = data
		prog = coreProgName
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("enforce: load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("enforce: load into kernel (need root + BPF-LSM): %w", err)
	}
	m, ok := coll.Maps[mapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("enforce: control map %q not found", mapName)
	}
	if err := setFlag(m, false); err != nil {
		coll.Close()
		return nil, err
	}
	// Pin without pre-emptive unlink: a successful Pin means this resident owns
	// the control channel, an EEXIST means another one already does.
	var pinnedCtl, pinnedInode bool
	if err := m.Pin(mapPinPath()); err != nil {
		coll.Close()
		if pinTaken(err) {
			return nil, residentBusyError("enforcer", "control map", mapPinPath())
		}
		return nil, fmt.Errorf("enforce: pin control map: %w", err)
	}
	pinnedCtl = true
	if core {
		im, ok := coll.Maps[inodeMapName]
		if !ok {
			removeCreatedPins(pinnedCtl, pinnedInode)
			coll.Close()
			return nil, fmt.Errorf("enforce: inode map %q not found in CO-RE object", inodeMapName)
		}
		if err := im.Pin(inodeMapPinPath()); err != nil {
			removeCreatedPins(pinnedCtl, pinnedInode)
			coll.Close()
			if pinTaken(err) {
				return nil, residentBusyError("enforcer", "inode map", inodeMapPinPath())
			}
			return nil, fmt.Errorf("enforce: pin inode map: %w", err)
		}
		pinnedInode = true
	}
	p, ok := coll.Programs[prog]
	if !ok {
		removeCreatedPins(pinnedCtl, pinnedInode)
		coll.Close()
		return nil, fmt.Errorf("enforce: program %q not found", prog)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: p})
	if err != nil {
		removeCreatedPins(pinnedCtl, pinnedInode)
		coll.Close()
		return nil, fmt.Errorf("enforce: attach LSM (need CONFIG_BPF_LSM and `bpf` in /sys/kernel/security/lsm): %w", err)
	}
	return &Guard{coll: coll, lnk: l, core: core, created: true}, nil
}

// Wait blocks until ctx is done (the resident enforcer loop).
func (g *Guard) Wait(ctx context.Context) { <-ctx.Done() }

// Close detaches the program and removes the pinned map — execution is no
// longer frozen once this returns. The link fd is closed first: enforcement
// lives only as long as that fd, so the policy is lifted before the pins go.
// Only pins this Load created are unlinked — the control path
// (SetPinned/StatusPinned via openPinned) opens a pinned map and closes it
// again, which closes the fd but keeps the bpffs entry, so it never unlinks
// the resident's control channel.
func (g *Guard) Close() error {
	var first error
	if g.lnk != nil {
		if err := g.lnk.Close(); err != nil {
			first = err
		}
	}
	if g.created {
		removeCreatedPins(true, g.core)
		g.created = false
	}
	if g.coll != nil {
		g.coll.Close()
	}
	return first
}

// Core reports whether this guard loaded the CO-RE path-aware object (and thus
// has a per-inode blocklist).
func (g *Guard) Core() bool { return g.core }

// BlockInode adds (block=true) or removes (block=false) a file from the pinned
// blocklist. Requires a CO-RE enforcer to be running (that map pinned).
func BlockInode(key BlockedFile, block bool) error {
	m, err := ebpf.LoadPinnedMap(inodeMapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("enforce: no CO-RE enforcer running (inode blocklist not pinned); start `enforce run --core <obj>`")
		}
		return fmt.Errorf("enforce: open inode blocklist: %w", err)
	}
	defer m.Close()
	if block {
		var v uint8 = 1
		return m.Update(&key, &v, ebpf.UpdateAny)
	}
	if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("enforce: unblock inode: %w", err)
	}
	return nil
}

// ListBlocked returns the files currently in the pinned blocklist.
func ListBlocked() ([]BlockedFile, error) {
	m, err := ebpf.LoadPinnedMap(inodeMapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("enforce: no CO-RE enforcer running (inode blocklist not pinned)")
		}
		return nil, fmt.Errorf("enforce: open inode blocklist: %w", err)
	}
	defer m.Close()
	var out []BlockedFile
	var key BlockedFile
	var val uint8
	it := m.Iterate()
	for it.Next(&key, &val) {
		out = append(out, key)
	}
	return out, it.Err()
}

// SetPinned flips the pinned control map without needing the resident Guard —
// the control path for `enforce on|off`. It errors if no enforcer is running
// (the map is not pinned).
func SetPinned(on bool) error {
	m, err := openPinned()
	if err != nil {
		return err
	}
	defer m.Close()
	return setFlag(m, on)
}

// StatusPinned reads the pinned control map (the `enforce status` path).
func StatusPinned() (bool, error) {
	m, err := openPinned()
	if err != nil {
		return false, err
	}
	defer m.Close()
	var key, val uint32
	if err := m.Lookup(&key, &val); err != nil {
		return false, fmt.Errorf("enforce: read control map: %w", err)
	}
	return val != 0, nil
}

func openPinned() (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(mapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("enforce: no resident enforcer is running (control map not pinned); start `cau-kernel enforce run` first")
		}
		return nil, fmt.Errorf("enforce: open pinned map: %w", err)
	}
	return m, nil
}

func setFlag(m *ebpf.Map, on bool) error {
	var key, val uint32
	if on {
		val = 1
	}
	if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("enforce: update control map: %w", err)
	}
	return nil
}
