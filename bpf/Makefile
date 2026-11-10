# Build the BPF-LSM guard objects. Needs clang with a bpf target (LLVM >= 10).
# On Debian/Kali the kernel UAPI asm headers live in a multiarch path, hence
# the -I below. Every object here is self-contained: it includes only
# <linux/bpf.h> and reads kernel structs through partial struct declarations
# carrying preserve_access_index, so the build needs NO libbpf-dev, NO
# bpftool and NO generated vmlinux.h — the plain `clang -target bpf` recipe
# below compiles them, CO-RE variants included.
#
#   make                 # build every object
#   make verify          # build + confirm the LSM program section is present
#   make verify-core     # + confirm the CO-RE file_open/task_kill sections
#
# The path-aware CO-RE variants (lsm_fileopen.bpf.c, lsm_killguard.bpf.c) build
# with exactly the same recipe; see README.md for what they add.

CLANG   ?= clang
ARCH    ?= x86
INCLUDE ?= -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS  := -target bpf -O2 -g -D__TARGET_ARCH_$(ARCH) $(INCLUDE)

OBJ := lsm_guard.bpf.o

COREOBJ := lsm_fileopen.bpf.o
KILLOBJ := lsm_killguard.bpf.o
NETOBJ := lsm_netshell.bpf.o

.PHONY: all verify core verify-core clean
all: $(OBJ) $(NETOBJ) $(COREOBJ) $(KILLOBJ)

# Self-contained like lsm_guard: partial structs with preserve_access_index, so
# it needs neither libbpf-dev nor a generated vmlinux.h.
$(NETOBJ): lsm_netshell.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(OBJ): lsm_guard.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# readelf -S truncates long section names to "lsm/ptrace_a[...]" in its default
# column width, so the check has to ask for the wide listing (-SW): a truncated
# name never matches, and the gate would fail on a perfectly good object.
verify: $(OBJ)
	@readelf -SW $(OBJ) 2>/dev/null | grep -q 'lsm/bprm' \
		&& echo "OK: BPF-LSM program section present" \
		|| { echo "FAIL: no lsm program section"; exit 1; }

# Optional convenience only: nothing in this Makefile needs a generated
# vmlinux.h (the sources include <linux/bpf.h> and use preserve_access_index
# with partial structs). If you ever write an object that does want full kernel
# types, this dumps the running kernel's BTF; it is otherwise unused, and
# `clean` removes it.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# The CO-RE variants build with the SAME plain clang recipe as the others: no
# libbpf-dev headers, no bpftool-generated vmlinux.h (see the header comment
# and README.md).
core: $(COREOBJ) $(KILLOBJ)

$(COREOBJ): lsm_fileopen.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(KILLOBJ): lsm_killguard.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

# The wide listing (-SW) is required here too: "lsm/ptrace_access_check" is
# longer than readelf's default column, and the truncated name it prints
# otherwise never matches the grep.
verify-core: core
	@readelf -SW $(COREOBJ) 2>/dev/null | grep -q 'lsm/file_open' \
		&& echo "OK: CO-RE BPF-LSM file_open section present" \
		|| { echo "FAIL: no lsm/file_open section"; exit 1; }
	@readelf -SW $(KILLOBJ) 2>/dev/null | grep -q 'lsm/task_kill' \
		&& echo "OK: CO-RE BPF-LSM task_kill section present" \
		|| { echo "FAIL: no lsm/task_kill section"; exit 1; }
	@readelf -SW $(KILLOBJ) 2>/dev/null | grep -q 'lsm/ptrace_access_check' \
		&& echo "OK: CO-RE BPF-LSM ptrace_access_check section present" \
		|| { echo "FAIL: no lsm/ptrace_access_check section"; exit 1; }

clean:
	rm -f $(OBJ) $(NETOBJ) $(COREOBJ) $(KILLOBJ) vmlinux.h
