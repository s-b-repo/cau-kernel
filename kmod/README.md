# cau_guard — kernel-module enforcement backend

A loadable kernel module that implements the same execution-freeze primitive as
the BPF-LSM guard, for the cases the roadmap reserves for "a minimal signed
out-of-tree module where BPF-LSM cannot serve."

## Why a module *and* a BPF-LSM program?

| | BPF-LSM (`bpf/`, default) | this module (`kmod/`) |
|---|---|---|
| Power | verifier-bounded; attaches only to LSM hooks | **arbitrary in-kernel C; kprobe any function; no verifier** |
| Safety | cannot crash the kernel; auto-detaches | a bug can panic; taints the kernel (O/E) |
| Trust | loaded via `bpf()` syscall | needs module signing for Secure Boot |
| Default? | **yes** | only where BPF-LSM is unavailable or insufficient |

"More capable than eBPF" is literal here — the module can mediate functions and
run logic eBPF cannot — but it is *not* the safer choice, and the sensor treats
BPF-LSM as the default. Pick the module when the kernel lacks `CONFIG_BPF_LSM`,
when `bpf` is absent from `/sys/kernel/security/lsm`, or when you need a hook
point eBPF cannot reach.

## Build

```sh
sudo apt-get install -y linux-headers-$(uname -r)   # or kernel-devel
make
```

CI builds this on every push (installs `linux-headers` on the runner), so the
module is proven to compile even though the sensor's own sandbox has no kernel
headers.

## Load and control (root)

```sh
sudo insmod cau_guard.ko
echo 1 | sudo tee /sys/module/cau_guard/parameters/enforce   # freeze execve
echo 0 | sudo tee /sys/module/cau_guard/parameters/enforce   # release
sudo rmmod cau_guard                                         # remove (releases)
```

It kretprobes `security_bprm_check` and overrides the return to `-EPERM` while
`enforce` is set. If that symbol is not kprobe-able on your build, load with a
different hook: `sudo insmod cau_guard.ko target=bprm_execve`.

## DKMS (rebuild across kernel upgrades)

```sh
sudo cp -r . /usr/src/cau-guard-0.1.0
sudo dkms add    -m cau-guard -v 0.1.0
sudo dkms build  -m cau-guard -v 0.1.0
sudo dkms install -m cau-guard -v 0.1.0
```

## Secure Boot

With Secure Boot on, the module must be signed by a key enrolled in MOK, or it
will be refused. Sign with the kernel's `scripts/sign-file` and your MOK key.
This matches the engine's signed-release posture: nothing privileged loads
unverified.
