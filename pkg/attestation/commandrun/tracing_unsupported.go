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
