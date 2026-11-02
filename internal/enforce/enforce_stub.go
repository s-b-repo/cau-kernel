//go:build !(linux && ebpf)

// This stub is compiled when the `ebpf` tag is absent (or off Linux), so the
// default binary builds everywhere with no eBPF toolchain and no cilium/ebpf
// dependency. Enforcement is unavailable; the CLI says so and points at the
// build instructions.
package enforce

import "context"

// Available reports whether this build has eBPF enforcement compiled in.
const Available = false

// Guard mirrors the eBPF build's shape so the command compiles identically.
type Guard struct{}

func Load() (*Guard, error)           { return nil, ErrUnavailable }
func (g *Guard) Wait(context.Context) {}
func (g *Guard) Close() error         { return nil }

func SetPinned(bool) error        { return ErrUnavailable }
func StatusPinned() (bool, error) { return false, ErrUnavailable }
