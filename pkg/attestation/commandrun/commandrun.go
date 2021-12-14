package commandrun

import (
	"bytes"
	"io"
	"os"
	"os/exec"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/artifact"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name = "CommandRun"
	Type = "https://witness.testifysec.com/attestations/CommandRun/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type Option func(*CommandRun)

func WithCommand(cmd []string) Option {
	return func(cr *CommandRun) {
		cr.Cmd = cmd
	}
}

func WithMaterials(materials map[string]cryptoutil.DigestSet) Option {
	return func(cr *CommandRun) {
		cr.materials = materials
	}
}

func WithTracing(enabled bool) Option {
	return func(cr *CommandRun) {
		cr.enableTracing = enabled
	}
}

func WithSilent(silent bool) Option {
	return func(cr *CommandRun) {
		cr.silent = silent
	}
}

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{}
	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

type ProcessInfo struct {
	ProcessID   int            `json:"processid"`
	Program     string         `json:"program,omitempty"`
	OpenedFiles map[string]int `json:"openedFiles,omitempty"`
}

type CommandRun struct {
	Cmd       []string           `json:"cmd"`
	Stdout    string             `json:"stdout,omitempty"`
	Stderr    string             `json:"stderr,omitempty"`
	ExitCode  int                `json:"exitcode"`
	Products  *artifact.Attestor `json:"products"`
	Processes []ProcessInfo      `json:"processes,omitempty"`

	silent        bool
	materials     map[string]cryptoutil.DigestSet
	enableTracing bool
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
	if len(rc.Cmd) == 0 {
		return attestation.ErrInvalidOption{
			Option: "Cmd",
			Reason: "CommandRun attestation requires a command to run",
		}
	}

	if len(rc.materials) <= 0 {
		for _, attestor := range ctx.CompletedAttestors() {
			if artifactAttestor, ok := attestor.(*artifact.Attestor); ok {
				rc.materials = artifactAttestor.Artifacts
			}
		}
	}

	if err := rc.runCmd(ctx); err != nil {
		return err
	}

	rc.Products = artifact.New(artifact.WithBaseArtifacts(rc.materials))
	return rc.Products.Attest(ctx)
}

func (rc *CommandRun) Name() string {
	return Name
}

func (rc *CommandRun) Type() string {
	return Type
}

func (rc *CommandRun) Subjects() map[string]cryptoutil.DigestSet {
	return rc.Products.Artifacts
}

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	c := exec.Command(r.Cmd[0], r.Cmd[1:]...)
	c.Dir = ctx.WorkingDir()
	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}
	if !r.silent {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}

	stdoutWriter := io.MultiWriter(stdoutWriters...)
	stderrWriter := io.MultiWriter(stderrWriters...)
	c.Stdout = stdoutWriter
	c.Stderr = stderrWriter
	if r.enableTracing {
		enableTracing(c)
	}

	if err := c.Start(); err != nil {
		return err
	}

	var err error
	if r.enableTracing {
		r.Processes, err = r.trace(c)
	} else {
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()
	return err
}
