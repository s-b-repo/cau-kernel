#!/usr/bin/env bash
#
# vm-test.sh — prove the BPF-LSM guards against the real kernel, without root.
#
# Boots the running kernel in QEMU with a one-program initramfs. /init (vmtest/)
# loads each guard through the real verifier and drives real execve calls, so a
# pass means the program loads and behaves on this exact kernel, which compiling
# it cannot show. The guest owns its whole kernel, so nothing here touches the
# host's LSM state.
#
# Needs: qemu-system-x86_64, a readable /boot/vmlinuz-$(uname -r), cpio, gzip.
# KERNEL=/path/to/bzImage tests a kernel other than the running one.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
kernel="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

[ -r "$kernel" ] || { echo "cannot read $kernel" >&2; exit 1; }

cd "$root"
CGO_ENABLED=0 go build -tags ebpf -ldflags '-s -w' -o "$work/init.bin" ./vmtest
CGO_ENABLED=0 go build -tags ebpf -ldflags '-s -w' -o "$work/cau-kernel" .

image="$work/image"
mkdir -p "$image"/{bin,tmp,proc,sys,dev}
cp "$work/init.bin" "$image/init"
cp bpf/lsm_fileopen.bpf.o "$image/lsm_fileopen.bpf.o"
cp "$work/cau-kernel" "$image/bin/cau-kernel"
cp "$work/init.bin" "$image/bin/sh"
cp "$work/init.bin" "$image/bin/plain"
cp "$work/init.bin" "$image/tmp/x"
printf '#!/bin/sh\n' > "$image/bin/script.sh"
chmod +x "$image/bin/script.sh"

(cd "$image" && find . -print0 | cpio --quiet --null -o -H newc --owner=0:0 | gzip -1) > "$work/initrd.gz"

accel=(-cpu max)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	accel=(-enable-kvm -cpu host)
fi

out="$work/serial.log"
timeout "${VM_TIMEOUT:-300}" qemu-system-x86_64 "${accel[@]}" -m 1024 -smp 2 \
	-kernel "$kernel" -initrd "$work/initrd.gz" \
	-append "console=ttyS0 panic=-1 quiet loglevel=3" \
	-nographic -no-reboot -nic none | tee "$out" | grep --line-buffered VMTEST || true

if [ -n "${VM_EVENTLOG:-}" ]; then
	sed -n 's/.*VMTEST EVENTLOG //p' "$out" | tr -d '\r' > "$VM_EVENTLOG"
fi
grep -q 'VMTEST RESULT passed=[1-9][0-9]* failed=0' "$out" || { echo "vm-test: FAILED" >&2; tail -20 "$out" >&2; exit 1; }
echo "vm-test: PASSED on $(basename "$kernel")"
