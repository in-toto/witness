//go:build linux && amd64

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint64 {
	return regs.Orig_rax
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Rdi),
		uintptr(regs.Rsi),
		uintptr(regs.Rdx),
		uintptr(regs.R10),
		uintptr(regs.R8),
		uintptr(regs.R9),
	}
}

func getNativeUint(n int) uint64 {
	return uint64(n)
}
