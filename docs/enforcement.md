# Enforcement

Two interchangeable backends implement the same primitive — an **execution
freeze**: while armed, every new `execve` is denied, so an attacker who has
tripped the tamper detectors cannot spawn further processes while the operator
responds. Both are **fail-open**: if the resident enforcer dies, the attachment
drops and execution resumes, so a bug can never permanently brick the host.

A freeze refuses only opens that load a program. Before 2026-11-07, with the file
guard loaded it refused every open, so nothing could read a log, write one, or run
`enforce off`; `make vm-test` now checks that files stay usable under a freeze.

## Network-shell guard

`cau ps` finds a reverse shell by polling `/proc`, so anything that runs between
two scans is invisible to it. `lsm_netshell.bpf.c` sits where that cannot happen:
`lsm/bprm_check_security` fires on every `execve`, before the new image runs, with
the descriptors the program will inherit already in place. A program whose stdin
and stdout are both an established `AF_INET` or `AF_INET6` socket is a reverse or
bind shell, whatever its command line says.

```sh
make enforce
sudo ./cau-kernel enforce netshell                  # audit everything, print JSON events
sudo ./cau-kernel enforce netshell --mode deny      # refuse interpreters on network stdio
sudo ./cau-kernel enforce netshell --mode deny --log /run/cau-kernel.jsonl
cau ps --kernel-events /run/cau-kernel.jsonl        # correlate with live processes
```

| Flag | Default | Applies to |
|---|---|---|
| `--mode` | `audit` | interpreters on network stdio (shells, Python, Perl, Ruby, PHP, Lua, Node, awk) |
| `--any-program` | `audit` | every program on network stdio, interpreters included, which catches `cp /bin/bash /tmp/x` |
| `--memfd` | `audit` | execution from a memfd, the fileless path nothing on disk records |

`--mode off` turns off the *interpreter* rule, not the check: the
any-program policy still applies to interpreters, so an interpreter on network
stdio is refused under `--mode off --any-program deny`. The two policies never
leave a program unexamined.

Start in audit: `deny` refuses a legitimate inetd-style service as readily as a
reverse shell, and `--memfd deny` breaks `runc`, which re-executes through a memfd.

What it deliberately does not refuse, all proven by `make vm-test`:

- a shell on an `AF_UNIX` socketpair, which is how OpenSSH runs `ssh host cmd`;
- a shell on a listening socket (inetd `Accept=no`);
- a shell with only one of stdin and stdout on the network;
- any of these with pipes.

Blind spots: a shell on a pty (`socat ... EXEC:sh,pty`, `python -c 'pty.spawn()'`)
and a pipe relay (`mkfifo | sh | nc`) have no socket on stdio at exec. `cau ps`
catches the relay, and the network tool's own argv, from userspace. A shell
started first and connected afterwards by an in-process implant passes the hook.

Like every guard here it fails open: the attachment lives with the process, so a
crash or `Ctrl-C` lifts the policy. `packaging/cau-kernel-guard.service` runs it,
and `cau defend --kernel-events` joins its log with the other layers.

Each event the guard writes says which process it happened to: the line
carries the process's start time (`start_ticks`, the same clock and unit as
field 22 of `/proc/<pid>/stat`), the thread that called `execve` (`tid`) and
the time the event was read (`time`). A PID is reused and the log outlives the
processes it names, so the start time is what lets the reader match an event to
the process it was about and to no other — and what lets it tell an exec the
guard *saw* from one it merely heard about later. The whole line is documented
in the README.

## Proving a guard

`make vm-test` boots the running kernel in QEMU with a one-program initramfs and
exercises the guards end to end, 57 scenarios on 7.1.5, the kill guard included: the real verifier loads
them, real `execve` calls run through the hooks, and the real `cau-kernel` binary
blocks a running process's file through `/proc/<pid>/exe`. It needs no root on the host, because the guest owns
its whole kernel. `KERNEL=/path/to/bzImage make vm-test` tests another kernel.

It also proves the event contract: the start time the guard records is compared
with the live process's own `starttime` field, on the real kernel, so the
number the engine matches on is the number `/proc` reports.

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
Loading needs root (or `CAP_BPF` + `CAP_MAC_ADMIN`) and a BPF-LSM kernel.

**One resident per pinned channel.** The kernel lets a pinned bpffs object be
opened by other processes but not replaced, so a second `enforce run` cannot
take the control map over: it refuses to start ("another enforcer is already
resident") rather than stealing the channel that the running resident's
`on`/`off`/`status` depends on. Only the resident that created a pin removes it,
on exit — and the control path (`on`, `off`, `status`, `block`, `unblock`,
`protect`) opens the pinned map, uses it and closes it again without ever
unlinking the pin. The killguard's protected-PID map follows the same rule.

A pin in bpffs is a filesystem entry, so it outlives the resident that made
it: a resident that was killed left its pin behind, and the next one was
refused for the same reason a live resident would be. The resident therefore
holds an advisory lock as well (`/run/cau-kernel/*.lock`), which the kernel
releases when the process dies however it dies. A pin that is still there with
the lock free belonged to a resident that is gone, and it is replaced. Stopping
the resident is the whole recovery: no pin to remove by hand.

### Path-aware policy (per-inode blocklist)

Load the CO-RE object (`make -C bpf lsm_fileopen.bpf.o`, no `libbpf-dev` needed) to
add per-file denial on top of the global freeze. Files are keyed on device and
inode, because inode numbers repeat across filesystems. `cau ps --respond stop
--block-exe` drives this for a confirmed implant, and refuses to block a system
path or an interpreter: the executable of a reverse shell is usually `/bin/bash`.

```sh
sudo ./cau-kernel enforce run --core bpf/lsm_fileopen.bpf.o   # resident, path-aware
sudo ./cau-kernel enforce block   /path/to/implant            # deny opening that file
sudo ./cau-kernel enforce unblock /path/to/implant
./cau-kernel enforce blocked                                   # list blocked files
```

`run --core` loads `lsm/file_open` and pins both the freeze flag and the
`cau_blocked_inodes` map; `block`/`unblock` resolve a path to its inode and flip
that pinned map, so a responder can quarantine a specific dropped file from being
opened while leaving the rest of the system running.

### Self-protection: kill/ptrace guard

Where the two guards above protect the host, this one protects the **sensor**:
it stops malware from killing or hooking the EDR, which is a standard attacker
move (ATT&CK **T1562.001**, Impair Defenses). It hooks `lsm/task_kill` to deny
every signal — including `SIGKILL`/`SIGSTOP`, which cannot be resisted from user
space — sent to a protected process, and `lsm/ptrace_access_check` to deny
debugger/injector attach. This is the kernel-level counterpart to the userspace
process-name randomisation in the scanner's `internal/harden` (which only hides
the sensor from name-based hunts like `pkill <name>`).

```sh
make -C bpf core                                                   # builds lsm_killguard.bpf.o
sudo ./cau-kernel enforce killguard --obj bpf/lsm_killguard.bpf.o  # resident: attach both hooks
sudo ./cau-kernel enforce protect   --pid "$(pgrep -x cau)"        # defend the sensor's PID
sudo ./cau-kernel enforce unprotect --pid 1234
./cau-kernel enforce protected                                     # list protected PIDs
```

`killguard` pins the `cau_protected_pids` map and attaches both LSM hooks;
`protect`/`unprotect` flip that pinned map by thread-group id. Nothing is
protected until a PID is added. Signals a protected process sends within its own
thread group are exempt, so it can still manage its own workers. Like the
enforcer's control map, the protected-PID pin belongs to the resident that
created it: a second `killguard` refuses to start rather than take it over, and
the pin is removed only when that resident exits.

Three honest limits:

- **Fail-open, by design.** The hooks live only as long as the resident
  `killguard`; kill *it* (it is not itself protected) and all protection lifts.
  So the operator can always recover — and `protect` refuses PID 1 and its own
  PID so the guard can never be made un-teardownable.
- **Attackers, not the kernel.** `security_task_kill` is consulted for
  user-space-originated signals; some kernel-internal paths (e.g. the OOM
  killer) do not pass through it.
- **Real kernel only.** A BPF-LSM program can be loaded and exercised only on a
  kernel with `CONFIG_BPF_LSM` and `bpf` in `/sys/kernel/security/lsm`, as root.
  CI (`make -C bpf verify-core`) only proves it *compiles*; it is never
  load-tested in the sandbox.

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
