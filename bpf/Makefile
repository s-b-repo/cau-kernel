# Build the BPF-LSM guard object. Needs clang with a bpf target (LLVM >= 10).
# On Debian/Kali the kernel UAPI asm headers live in a multiarch path, hence
# the -I below. This self-contained build needs NO libbpf-dev and NO vmlinux.h.
#
#   make                 # build lsm_guard.bpf.o
#   make verify          # build + confirm the LSM program section is present
#
# The production, path-aware CO-RE variant (see README.md) instead needs
# libbpf-dev and a bpftool-generated vmlinux.h.

CLANG   ?= clang
ARCH    ?= x86
INCLUDE ?= -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS  := -target bpf -O2 -g -D__TARGET_ARCH_$(ARCH) $(INCLUDE)

OBJ := lsm_guard.bpf.o

COREOBJ := lsm_fileopen.bpf.o
KILLOBJ := lsm_killguard.bpf.o
NETOBJ := lsm_netshell.bpf.o

.PHONY: all verify core verify-core clean
all: $(OBJ) $(NETOBJ) $(COREOBJ)

# Self-contained like lsm_guard: partial structs with preserve_access_index, so
# it needs neither libbpf-dev nor a generated vmlinux.h.
$(NETOBJ): lsm_netshell.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(OBJ): lsm_guard.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

verify: $(OBJ)
	@readelf -S $(OBJ) 2>/dev/null | grep -q 'lsm/bprm' \
		&& echo "OK: BPF-LSM program section present" \
		|| { echo "FAIL: no lsm program section"; exit 1; }

# The CO-RE variant needs libbpf-dev headers and a bpftool-generated vmlinux.h.
# `make core` generates vmlinux.h (if missing) from the running kernel's BTF.
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

core: vmlinux.h $(COREOBJ) $(KILLOBJ)

$(COREOBJ): lsm_fileopen.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

$(KILLOBJ): lsm_killguard.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

verify-core: core
	@readelf -S $(COREOBJ) 2>/dev/null | grep -q 'lsm/file_open' \
		&& echo "OK: CO-RE BPF-LSM file_open section present" \
		|| { echo "FAIL: no lsm/file_open section"; exit 1; }
	@readelf -S $(KILLOBJ) 2>/dev/null | grep -q 'lsm/task_kill' \
		&& echo "OK: CO-RE BPF-LSM task_kill section present" \
		|| { echo "FAIL: no lsm/task_kill section"; exit 1; }
	@readelf -S $(KILLOBJ) 2>/dev/null | grep -q 'lsm/ptrace_access_check' \
		&& echo "OK: CO-RE BPF-LSM ptrace_access_check section present" \
		|| { echo "FAIL: no lsm/ptrace_access_check section"; exit 1; }

clean:
	rm -f $(OBJ) $(NETOBJ) $(COREOBJ) $(KILLOBJ) vmlinux.h
