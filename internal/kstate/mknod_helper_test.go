package kstate

import "syscall"

// mknodChar creates a /dev/mem-style character device (1,1) at path when the
// environment permits it (unprivileged users get EPERM, in which case the
// caller asserts only the type bit of a regular file).
func mknodChar(path string) error {
	return syscall.Mknod(path, syscall.S_IFCHR|0o600, 1<<8|1)
}
