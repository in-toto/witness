package run

import (
	"context"
	"crypto"
	"fmt"
	"os"
)

type ErrInvalidRunOptions struct {
	Option string
	Reason string
}

func (e ErrInvalidRunOptions) Error() string {
	return fmt.Sprintf("invalid value for option %v: %v", e.Option, e.Reason)
}

type Context struct {
	ctx        context.Context
	commands   [][]string
	workingDir string
	hashes     []crypto.Hash
}

type Result struct {
	Environment    Environment
	Artifacts      map[string]Artifact
	CommandResults []CommandResult
}

type RunOption func(r *Context)

func WithCommands(cmds [][]string) RunOption {
	return func(r *Context) {
		for _, cmd := range cmds {
			if len(cmd) <= 0 {
				continue
			}

			r.commands = append(r.commands, cmd)
		}
	}
}

func WithWorkingDir(workingDir string) RunOption {
	return func(r *Context) {
		if workingDir != "" {
			r.workingDir = workingDir
		}
	}
}

func WithContext(ctx context.Context) RunOption {
	return func(r *Context) {
		r.ctx = ctx
	}
}

func WithHashes(hashes []crypto.Hash) RunOption {
	return func(r *Context) {
		if len(hashes) > 0 {
			r.hashes = hashes
		}
	}
}

func New(opts ...RunOption) (*Context, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	r := &Context{
		ctx:        context.Background(),
		commands:   make([][]string, 0),
		hashes:     []crypto.Hash{crypto.SHA256},
		workingDir: wd,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r, nil
}

func (r *Context) Run() (Result, error) {
	result := Result{
		Environment: recordEnvironment(),
	}

	initialArtifacts, err := recordArtifacts(r.workingDir, map[string]Artifact{}, r.hashes)
	if err != nil {
		return Result{}, err
	}

	result.Artifacts = initialArtifacts

	// lastArtifacts is the current view of all artifacts after each command is run.
	// we start off by cloning initialArtifacts and then layer the artifacts from each command on top
	lastArtifacts := make(map[string]Artifact)
	for path, artifact := range initialArtifacts {
		lastArtifacts[path] = artifact
	}

	for _, cmd := range r.commands {
		cmdResult, err := r.runCmd(cmd)
		if err != nil {
			return result, err
		}

		cmdArtifacts, err := recordArtifacts(r.workingDir, lastArtifacts, r.hashes)
		if err != nil {
			return result, err
		}

		for path, artifact := range cmdArtifacts {
			lastArtifacts[path] = artifact
		}

		cmdResult.Artifacts = cmdArtifacts
		result.CommandResults = append(result.CommandResults, cmdResult)
	}

	return result, nil
}
