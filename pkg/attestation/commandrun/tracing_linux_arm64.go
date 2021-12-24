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
