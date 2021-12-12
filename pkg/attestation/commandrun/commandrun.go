package commandrun

import (
	"io"
	"os/exec"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/artifact"
	"github.com/testifysec/witness/pkg/crypto"
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

func WithMaterials(materials map[string]crypto.DigestSet) Option {
	return func(cr *CommandRun) {
		cr.materials = materials
	}
}

func WithTracing(enabled bool) Option {
	return func(cr *CommandRun) {
		cr.enableTracing = enabled
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
	SHA256      string         `json:"sha256,omitempty"`
	OpenedFiles map[string]int `json:"openedFiles,omitempty"`
	ParentPid   int            `json:"parentPid,omitempty"`
	Comm        string         `json:"comm,omitempty"`
	Environ     string         `json:"environ,omitempty"`
}

type CommandRun struct {
	Cmd       []string           `json:"cmd"`
	Stdout    string             `json:"stdout,omitempty"`
	Stderr    string             `json:"stderr,omitempty"`
	ExitCode  int                `json:"exitcode"`
	Products  *artifact.Attestor `json:"products"`
	Processes []ProcessInfo      `json:"processes,omitempty"`

	materials     map[string]crypto.DigestSet
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

func (rc *CommandRun) Subjects() map[string]crypto.DigestSet {
	return rc.Products.Artifacts
}

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	c := exec.Command(r.Cmd[0], r.Cmd[1:]...)
	c.Dir = ctx.WorkingDir()
	stdoutReader, err := c.StdoutPipe()
	if err != nil {
		return err
	}

	stderrReader, err := c.StderrPipe()
	if err != nil {
		return err
	}

	if r.enableTracing {
		enableTracing(c)
	}

	if err := c.Start(); err != nil {
		return err
	}

	if r.enableTracing {
		r.Processes, err = r.trace(c)
	} else {
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	stdout, _ := io.ReadAll(stdoutReader)
	stderr, _ := io.ReadAll(stderrReader)
	r.Stdout = string(stdout)
	r.Stderr = string(stderr)
	return err
}
