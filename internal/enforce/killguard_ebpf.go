//go:build linux && ebpf

// Kill/ptrace guard loader. Where the exec-freeze guard and the per-inode
// fileopen guard protect the host, this protects the SENSOR itself: a resident
// process attaches lsm/task_kill and lsm/ptrace_access_check and pins the
// protected-PID map to bpffs, so a control invocation can add or remove the
// PIDs to defend. Same fail-open model as the other guards — the attachments
// die with the resident process, so protection can never outlive it and brick
// the host.
package enforce

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	killProgKill   = "cau_task_kill"
	killProgPtrace = "cau_ptrace"
	pidsMapName    = "cau_protected_pids"
)

func pidsMapPinPath() string { return filepath.Join(pinDir, pidsMapName) }

// KillGuard holds the resident lsm/task_kill + lsm/ptrace_access_check
// attachments and owns the pinned protected-PID map.
type KillGuard struct {
	coll    *ebpf.Collection
	links   []link.Link
	created bool
	lock    *residentLock
}

// LoadKillGuard loads the CO-RE kill/ptrace object from objPath
// (bpf/lsm_killguard.bpf.o), attaches both LSM programs, and pins the
// protected-PID map to bpffs so `enforce protect` can reach it. The caller runs
// the resident loop and Closes on exit; Close detaches both hooks and removes
// the pin, lifting protection.
func LoadKillGuard(objPath string) (*KillGuard, error) {
	if objPath == "" {
		return nil, errors.New("enforce: killguard needs the CO-RE object path (bpf/lsm_killguard.bpf.o)")
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return nil, fmt.Errorf("enforce: create bpffs pin dir %s (is bpffs mounted?): %w", pinDir, err)
	}
	data, err := os.ReadFile(objPath)
	if err != nil {
		return nil, fmt.Errorf("enforce: read killguard object %s: %w", objPath, err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("enforce: load killguard spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("enforce: load killguard into kernel (need root + BPF-LSM): %w", err)
	}

	m, ok := coll.Maps[pidsMapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("enforce: protected-PID map %q not found in object", pidsMapName)
	}
	// Same one-resident rule as the enforcer's control map: EEXIST means
	// another killguard owns the pinned set, and stealing it would let that
	// guard's Close unlink the pin a live resident depends on. A pin left
	// behind by a killguard that was killed is stale, and the lock tells the
	// two apart.
	lock, err := takeResidentLock("killguard")
	if err != nil {
		coll.Close()
		return nil, err
	}
	if err := pinChannel(m, pidsMapPinPath(), lock); err != nil {
		coll.Close()
		lock.release()
		if pinTaken(err) {
			return nil, residentBusyError("killguard", "protected-PID map", pidsMapPinPath())
		}
		return nil, fmt.Errorf("enforce: pin protected-PID map: %w", err)
	}

	g := &KillGuard{coll: coll, created: true, lock: lock}
	for _, name := range []string{killProgKill, killProgPtrace} {
		p, ok := coll.Programs[name]
		if !ok {
			g.teardown()
			return nil, fmt.Errorf("enforce: program %q not found in object", name)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			g.teardown()
			return nil, fmt.Errorf("enforce: attach %s (need CONFIG_BPF_LSM and `bpf` in /sys/kernel/security/lsm): %w", name, err)
		}
		g.links = append(g.links, l)
	}
	return g, nil
}

// teardown releases whatever was attached/pinned so far (used on partial
// failure and by Close). Links go first so the hooks detach before the pin
// disappears; only a pin this Load created is unlinked, never a pin a second,
// refused-to-start resident would have stolen.
func (g *KillGuard) teardown() {
	for _, l := range g.links {
		if l != nil {
			_ = l.Close()
		}
	}
	g.links = nil
	if g.created {
		_ = os.Remove(pidsMapPinPath())
		g.created = false
	}
	if g.coll != nil {
		g.coll.Close()
	}
	g.lock.release()
}

// Wait blocks until ctx is done (the resident loop).
func (g *KillGuard) Wait(ctx context.Context) { <-ctx.Done() }

// Close detaches both hooks and removes the pinned map — protection is lifted
// once this returns.
func (g *KillGuard) Close() error {
	g.teardown()
	return nil
}

// ProtectPID adds (on=true) or removes (on=false) a thread-group id from the
// pinned protected set. Requires a killguard resident (map pinned).
func ProtectPID(pid uint32, on bool) error {
	m, err := ebpf.LoadPinnedMap(pidsMapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("enforce: no killguard running (protected-PID map not pinned); start `enforce killguard --obj bpf/lsm_killguard.bpf.o`")
		}
		return fmt.Errorf("enforce: open protected-PID map: %w", err)
	}
	defer m.Close()
	if on {
		var v uint8 = 1
		return m.Update(&pid, &v, ebpf.UpdateAny)
	}
	if err := m.Delete(&pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("enforce: unprotect pid: %w", err)
	}
	return nil
}

// ListProtected returns the thread-group ids currently in the pinned set.
func ListProtected() ([]uint32, error) {
	m, err := ebpf.LoadPinnedMap(pidsMapPinPath(), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("enforce: no killguard running (protected-PID map not pinned)")
		}
		return nil, fmt.Errorf("enforce: open protected-PID map: %w", err)
	}
	defer m.Close()
	var out []uint32
	var key uint32
	var val uint8
	it := m.Iterate()
	for it.Next(&key, &val) {
		out = append(out, key)
	}
	return out, it.Err()
}
