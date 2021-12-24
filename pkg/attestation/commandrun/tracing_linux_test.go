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

//go:build linux

package commandrun

import "testing"

const (
	status = `
Name:   blkcg_punt_bio
Umask:  0000
State:  I (idle)
Tgid:   214
Ngid:   0
Pid:    214
PPid:   2
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 64
Groups:  
NStgid: 214
NSpid:  214
NSpgid: 0
NSsid:  0
Threads:        1
SigQ:   0/514646
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: ffffffffffffffff
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        2
nonvoluntary_ctxt_switches:     0
	`
)

func Test_getPPIDFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	ppid, err := getPPIDFromStatus(byteStatus)
	if err != nil {
		t.Errorf("getPPIDFromStatus() error = %v", err)
		return
	}

	if ppid != 2 {
		t.Errorf("getPPIDFromStatus() = %v, want %v", ppid, 2)
	}

}

func Test_getSpecBypassIsVulnFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	isVuln := getSpecBypassIsVulnFromStatus(byteStatus)

	if isVuln != true {
		t.Errorf("getSpecBypassIsVulnFromStatus() = %v, want %v", isVuln, true)
	}

}
