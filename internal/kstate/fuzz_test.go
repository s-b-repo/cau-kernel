package kstate

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzCollect writes arbitrary bytes into the kernel-state files the collector
// parses and asserts it never panics — /proc/modules, the taint file, mounts,
// and the sysfs nodes are all attacker-influenceable on a compromised host, so
// the reader must survive any contents.
func FuzzCollect(f *testing.F) {
	f.Add([]byte("nf_tables 299008 1 nf_nat, Live 0xffffffffc0800000\n"), []byte("12288\n"), []byte("none /sys/fs/bpf bpf rw 0 0\n"))
	f.Add([]byte("short\na b c\n"), []byte("notanumber"), []byte(""))
	f.Add([]byte(""), []byte(""), []byte(""))
	f.Add([]byte("\x00\x01\x02\n\n\n"), []byte("\xff\xff"), []byte("garbage mounts"))

	f.Fuzz(func(t *testing.T, modules, tainted, mounts []byte) {
		root := t.TempDir()
		write := func(rel string, b []byte) {
			p := filepath.Join(root, rel)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, b, 0o644)
		}
		write("proc/modules", modules)
		write("proc/sys/kernel/tainted", tainted)
		write("proc/mounts", mounts)
		// Also feed the fuzz bytes to a PCR node and the IMA log.
		write("sys/class/tpm/tpm0/pcr-sha256/0", modules)
		write("sys/kernel/security/ima/runtime_measurements_count", tainted)

		c := Collector{Root: root}
		_ = c.Collect()  // must not panic
		_ = c.Measured() // must not panic
	})
}
