//go:build linux && arm

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getSyscallId(regs unix.PtraceRegs) uint32 {
	// arm32 has some nuance here with OABI vs EABI... punting for now and just using R7
	return regs.Uregs[7]
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return []uintptr{
		uintptr(regs.Uregs[0]),
		uintptr(regs.Uregs[1]),
		uintptr(regs.Uregs[2]),
		uintptr(regs.Uregs[3]),
		uintptr(regs.Uregs[4]),
		uintptr(regs.Uregs[5]),
	}
}

func getNativeUint(n int) uint32 {
	return uint32(n)
}
