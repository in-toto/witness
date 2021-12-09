//go:build linux && arm64

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint64 {
	return regs.Regs[8]
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Regs[0]),
		uintptr(regs.Regs[1]),
		uintptr(regs.Regs[2]),
		uintptr(regs.Regs[3]),
		uintptr(regs.Regs[4]),
		uintptr(regs.Regs[5]),
	}
}

func getNativeUint(n int) uint64 {
	return uint64(n)
}
