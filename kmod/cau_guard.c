// SPDX-License-Identifier: GPL-2.0
//
// cau_guard — the loadable-kernel-module enforcement backend for cau-kernel.
//
// Why a module when we also ship a BPF-LSM program? Because a module is *more
// capable where BPF-LSM cannot serve*: it runs arbitrary in-kernel C with no
// verifier restrictions, can hook functions no eBPF program may attach to, and
// makes synchronous allow/deny decisions with unbounded logic. The trade-off is
// honest and real: it is out-of-tree, it taints the kernel (O/E), a bug can
// panic the host, and it must be signed for Secure Boot. BPF-LSM stays the
// safer default; this is the heavier hammer the roadmap calls for "where BPF-LSM
// cannot serve".
//
// What it does: a kretprobe on security_bprm_check overrides the return value to
// -EPERM while the writable module parameter `enforce` is non-zero, freezing all
// new program execution under a verified tamper response. Clearing the parameter
// restores normal operation. Scope is deliberately the same execution-freeze
// primitive as the BPF-LSM guard, so the two backends are interchangeable.
//
// Control (root):
//   insmod cau_guard.ko
//   echo 1 > /sys/module/cau_guard/parameters/enforce   # freeze execve
//   echo 0 > /sys/module/cau_guard/parameters/enforce   # release
//   rmmod cau_guard                                      # remove (also releases)
//
// Symbol note: security_bprm_check is the LSM entry the kernel calls to vet an
// exec. If it is not kprobe-able on a given build, set `target=` to an available
// symbol (e.g. bprm_execve) at load time.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/err.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cau-edr");
MODULE_DESCRIPTION("cau-kernel execution-freeze guard (kretprobe mediation backend)");
MODULE_VERSION("0.1.0");

static int enforce;
module_param(enforce, int, 0644);
MODULE_PARM_DESC(enforce, "non-zero freezes new program execution (deny execve)");

static char *target = "security_bprm_check";
module_param(target, charp, 0444);
MODULE_PARM_DESC(target, "kernel symbol to gate exec on (default security_bprm_check)");

// ret_handler runs when the probed function returns. While enforce is set we
// override a success (>= 0) with -EPERM; we never flip an existing denial.
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	long ret = regs_return_value(regs);

	if (READ_ONCE(enforce) && ret == 0) {
		regs_set_return_value(regs, -EPERM);
		pr_warn_ratelimited("cau_guard: execution frozen, denied exec (%s)\n", target);
	}
	return 0;
}

static struct kretprobe guard_probe = {
	.handler        = ret_handler,
	// Each exec in flight holds an instance, and the exec check can sleep (IMA,
	// FUSE), so concurrency is not bounded by CPU count. A probe with no instance
	// free is missed, and a missed probe is an exec the freeze let through.
	.maxactive      = 1024,
};

static int __init cau_guard_init(void)
{
	int err;

	guard_probe.kp.symbol_name = target;
	err = register_kretprobe(&guard_probe);
	if (err < 0) {
		pr_err("cau_guard: register_kretprobe(%s) failed: %d\n", target, err);
		return err;
	}
	pr_info("cau_guard: attached to %s (enforce=%d)\n", target, enforce);
	return 0;
}

static void __exit cau_guard_exit(void)
{
	unregister_kretprobe(&guard_probe);
	pr_info("cau_guard: detached from %s (%d missed)\n", target, guard_probe.nmissed);
}

module_init(cau_guard_init);
module_exit(cau_guard_exit);
