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

//go:build !linux

package commandrun

import (
	"errors"
	"os/exec"

	"github.com/testifysec/witness/pkg/attestation"
)

func enableTracing(c *exec.Cmd) {
}

func (rc *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	return nil, errors.New("tracing not supported on this platform")
}
