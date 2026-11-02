# Enforcement

Two interchangeable backends implement the same primitive — an **execution
freeze**: while armed, every new `execve` is denied, so an attacker who has
tripped the tamper detectors cannot spawn further processes while the operator
responds. Both are **fail-open**: if the resident enforcer dies, the attachment
drops and execution resumes, so a bug can never permanently brick the host.

## Which backend?

| | BPF-LSM (`bpf/` + `cau-kernel enforce`) | kernel module (`kmod/cau_guard.ko`) |
|---|---|---|
| Default | **yes (safer)** | only where BPF-LSM cannot serve |
| Power | verifier-bounded; LSM hooks | arbitrary in-kernel C; any kprobe |
| Risk | cannot panic the kernel | can panic; taints kernel (O/E) |
| Needs | `CONFIG_BPF_LSM` + `bpf` in `/sys/kernel/security/lsm` | kernel headers to build; MOK signing under Secure Boot |

Pick the module when the kernel has no BPF-LSM, when `bpf` is absent from the LSM
list, or when you need a hook eBPF cannot reach — accepting that it is the
heavier, less-safe hammer.

## BPF-LSM guard

Built with the `ebpf` tag (`make enforce`); the default binary omits it and
reports enforcement unavailable.

```sh
make enforce                      # compile the object + build -tags ebpf
sudo ./cau-kernel enforce run     # resident: attach the guard, state = allow
sudo ./cau-kernel enforce on      # freeze: deny every new execve
sudo ./cau-kernel enforce off     # release
./cau-kernel enforce status       # report state (reads the pinned control map)
```

`run` attaches the program to `lsm/bprm_check_security` and pins the control map
to `/sys/fs/bpf/cau-kernel`; `on`/`off`/`status` flip or read that pinned map.
The attachment lives only as long as `run`, so killing it releases the freeze.
Loading needs root (or `CAP_BPF` + `CAP_MAC_ADMIN`) and a BPF-LSM kernel. See
[`bpf/README.md`](../bpf/README.md), including the CO-RE path-aware policy variant.

## Kernel module

```sh
sudo apt-get install -y linux-headers-$(uname -r)
make -C kmod                      # build cau_guard.ko
sudo insmod kmod/cau_guard.ko
echo 1 | sudo tee /sys/module/cau_guard/parameters/enforce   # freeze
echo 0 | sudo tee /sys/module/cau_guard/parameters/enforce   # release
sudo rmmod cau_guard
```

It kretprobes `security_bprm_check` and overrides the return to `-EPERM` while
`enforce` is set. DKMS packaging and Secure Boot signing are in
[`kmod/README.md`](../kmod/README.md).

## Response integration

A responder wires detection to enforcement: run `cau-kernel drift --pubkey` (or
`attest verify`) on a schedule; on a confirmed alert that policy says to contain,
arm the freeze (`enforce on`), capture evidence, and investigate. Because the
freeze is fail-open and reversible, it is a containment pause, not an
irreversible lockout.
