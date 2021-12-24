// Copyright 2021 The TestifySec Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
