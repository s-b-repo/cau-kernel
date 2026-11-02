package enforce

import "errors"

// ErrUnavailable is returned by the default (non-eBPF) build's enforcement
// operations, and is the message the CLI shows when enforcement was not
// compiled in. Declared here (untagged) so both builds share one definition.
var ErrUnavailable = errors.New("enforce: this binary was built without eBPF enforcement; rebuild with `make enforce` (needs clang + a BPF-LSM kernel), see bpf/README.md")
