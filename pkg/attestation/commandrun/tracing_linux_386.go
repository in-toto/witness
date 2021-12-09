//go:build linux && 386

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) int32 {
	return regs.Orig_eax
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Ebx),
		uintptr(regs.Ecx),
		uintptr(regs.Edx),
		uintptr(regs.Esi),
		uintptr(regs.Edi),
		uintptr(regs.Ebp),
	}
}

func getNativeUint(n int) uint32 {
	return uint32(n)
}
