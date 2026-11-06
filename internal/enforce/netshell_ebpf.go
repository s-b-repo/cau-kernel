//go:build linux && ebpf

package enforce

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed lsm_netshell.bpf.o
var netshellObject []byte

const (
	netshellProg     = "cau_netshell_guard"
	netshellPolicy   = "cau_policy"
	netshellNames    = "cau_interpreters"
	netshellEventMap = "cau_events"

	policyNetshell = 0
	policyMemfd    = 1
	policyAny      = 2
)

// NetshellGuard is the attached network-shell guard. Like every guard here it
// fails open: the LSM link lives only as long as this process, so when the
// process exits or Close is called the policy is gone.
type NetshellGuard struct {
	coll   *ebpf.Collection
	lnk    link.Link
	events *ringbuf.Reader
}

// LoadNetshell verifies, configures and attaches the guard. The policy is
// written before the attach, so the hook never runs half-configured.
func LoadNetshell(cfg NetshellConfig) (*NetshellGuard, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netshellObject))
	if err != nil {
		return nil, fmt.Errorf("enforce: parse netshell object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("enforce: verifier rejected the netshell guard: %+v", ve)
		}
		return nil, fmt.Errorf("enforce: load netshell guard: %w", err)
	}
	g := &NetshellGuard{coll: coll}
	if err := g.configure(cfg); err != nil {
		g.Close()
		return nil, err
	}
	if g.events, err = ringbuf.NewReader(coll.Maps[netshellEventMap]); err != nil {
		g.Close()
		return nil, fmt.Errorf("enforce: open event ring: %w", err)
	}
	if g.lnk, err = link.AttachLSM(link.LSMOptions{Program: coll.Programs[netshellProg]}); err != nil {
		g.Close()
		return nil, fmt.Errorf("enforce: attach LSM (need CONFIG_BPF_LSM and `bpf` in /sys/kernel/security/lsm): %w", err)
	}
	return g, nil
}

func (g *NetshellGuard) configure(cfg NetshellConfig) error {
	names := g.coll.Maps[netshellNames]
	var one uint8 = 1
	for _, n := range Interpreters() {
		var key [16]byte
		copy(key[:], n)
		if err := names.Update(&key, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("enforce: load interpreter names: %w", err)
		}
	}
	policy := g.coll.Maps[netshellPolicy]
	for key, mode := range map[uint32]Mode{policyNetshell: cfg.Interpreters, policyMemfd: cfg.Memfd, policyAny: cfg.AnyProgram} {
		v := uint32(mode)
		if err := policy.Update(&key, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("enforce: set policy: %w", err)
		}
	}
	return nil
}

// Events delivers guard events until ctx is done.
func (g *NetshellGuard) Events(ctx context.Context, fn func(Event)) error {
	stop := context.AfterFunc(ctx, func() { _ = g.events.Close() })
	defer stop()
	for {
		rec, err := g.events.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("enforce: read event: %w", err)
		}
		if e, err := DecodeEvent(rec.RawSample); err == nil {
			fn(e)
		}
	}
}

// Close detaches the guard, lifting the policy.
func (g *NetshellGuard) Close() error {
	var first error
	if g.lnk != nil {
		first = g.lnk.Close()
	}
	if g.events != nil {
		_ = g.events.Close()
	}
	if g.coll != nil {
		g.coll.Close()
	}
	return first
}
