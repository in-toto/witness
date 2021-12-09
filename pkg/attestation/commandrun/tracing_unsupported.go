//go:build !linux

package commandrun

import (
	"errors"
	"os/exec"
)

func enableTracing(c *exec.Cmd) {
}

func (rc *CommandRun) trace(c *exec.Cmd) ([]ProcessInfo, error) {
	return nil, errors.New("tracing not supported on this platform")
}
