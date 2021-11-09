package run

import (
	"io"
	"os/exec"
)

type CommandResult struct {
	Cmd      string
	Args     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	// Artifacts is a map of artifacts that the command modified or created during it's run
	Artifacts map[string]Artifact
}

func (r *Context) runCmd(cmdAndArgs []string) (CommandResult, error) {
	res := CommandResult{}
	res.Cmd = cmdAndArgs[0]
	res.Args = cmdAndArgs[1:]
	c := exec.Command(res.Cmd, res.Args...)
	c.Dir = r.workingDir
	stdoutReader, err := c.StdoutPipe()
	if err != nil {
		return res, err
	}

	stderrReader, err := c.StderrPipe()
	if err != nil {
		return res, err
	}

	if err := c.Start(); err != nil {
		return res, nil
	}

	res.Stdout, _ = io.ReadAll(stdoutReader)
	res.Stderr, _ = io.ReadAll(stderrReader)
	err = c.Wait()
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
	}

	return res, err
}
