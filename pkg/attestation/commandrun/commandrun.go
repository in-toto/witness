package commandrun

import (
	"io"
	"os/exec"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/attestation/artifact"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

const (
	Name = "CommandRun"
	URI  = "https://witness.testifysec.com/attestations/CommandRun/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, URI, func() attestation.Attestor {
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

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{}
	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

type CommandRun struct {
	Cmd      []string           `json:"cmd"`
	Stdout   string             `json:"stdout,omitempty"`
	Stderr   string             `json:"stderr,omitempty"`
	ExitCode int                `json:"exitcode"`
	Products *artifact.Attestor `json:"products"`

	materials map[string]crypto.DigestSet
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

func (rc *CommandRun) URI() string {
	return URI
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

	if err := c.Start(); err != nil {
		return nil
	}

	stdout, _ := io.ReadAll(stdoutReader)
	stderr, _ := io.ReadAll(stderrReader)
	r.Stdout = string(stdout)
	r.Stderr = string(stderr)
	err = c.Wait()
	if exitErr, ok := err.(*exec.ExitError); ok {
		r.ExitCode = exitErr.ExitCode()
	}

	return err
}
