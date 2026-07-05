package box

import (
	"syscall"
	"unsafe"
)

func setProcessName(name string) {
	var buf [16]byte
	copy(buf[:len(buf)-1], name)
	_, _, _ = syscall.Syscall6(syscall.SYS_PRCTL, 15, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0, 0)
}
