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
// the enforcer; Close detaches the program and removes the pinned maps.
type Guard struct {
	coll *ebpf.Collection
	lnk  link.Link
	core bool
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
	_ = os.Remove(mapPinPath())
	if err := m.Pin(mapPinPath()); err != nil {
		coll.Close()
		return nil, fmt.Errorf("enforce: pin control map: %w", err)
	}
	if core {
		im, ok := coll.Maps[inodeMapName]
		if !ok {
			_ = os.Remove(mapPinPath())
			coll.Close()
			return nil, fmt.Errorf("enforce: inode map %q not found in CO-RE object", inodeMapName)
		}
		_ = os.Remove(inodeMapPinPath())
		if err := im.Pin(inodeMapPinPath()); err != nil {
			_ = os.Remove(mapPinPath())
			coll.Close()
			return nil, fmt.Errorf("enforce: pin inode map: %w", err)
		}
	}
	p, ok := coll.Programs[prog]
	if !ok {
		_ = os.Remove(mapPinPath())
		_ = os.Remove(inodeMapPinPath())
		coll.Close()
		return nil, fmt.Errorf("enforce: program %q not found", prog)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: p})
	if err != nil {
		_ = os.Remove(mapPinPath())
		_ = os.Remove(inodeMapPinPath())
		coll.Close()
		return nil, fmt.Errorf("enforce: attach LSM (need CONFIG_BPF_LSM and `bpf` in /sys/kernel/security/lsm): %w", err)
	}
	return &Guard{coll: coll, lnk: l, core: core}, nil
}

// Wait blocks until ctx is done (the resident enforcer loop).
func (g *Guard) Wait(ctx context.Context) { <-ctx.Done() }

// Close detaches the program and removes the pinned map — execution is no
// longer frozen once this returns.
func (g *Guard) Close() error {
	var first error
	if g.lnk != nil {
		if err := g.lnk.Close(); err != nil {
			first = err
		}
	}
	_ = os.Remove(mapPinPath())
	if g.core {
		_ = os.Remove(inodeMapPinPath())
	}
	if g.coll != nil {
		g.coll.Close()
	}
	return first
}

// Core reports whether this guard loaded the CO-RE path-aware object (and thus
// has a per-inode blocklist).
func (g *Guard) Core() bool { return g.core }

// BlockInode adds (block=true) or removes (block=false) an inode from the pinned
// per-inode blocklist. Requires a CO-RE enforcer to be running (that map pinned).
func BlockInode(ino uint64, block bool) error {
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
		return m.Update(&ino, &v, ebpf.UpdateAny)
	}
	if err := m.Delete(&ino); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("enforce: unblock inode: %w", err)
	}
	return nil
}

// ListBlocked returns the inodes currently in the pinned blocklist.
func ListBlocked() ([]uint64, error) {
	m, err := ebpf.LoadPinnedMap(inodeMapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("enforce: no CO-RE enforcer running (inode blocklist not pinned)")
		}
		return nil, fmt.Errorf("enforce: open inode blocklist: %w", err)
	}
	defer m.Close()
	var out []uint64
	var key uint64
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
