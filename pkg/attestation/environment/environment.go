package environment

import (
	"os"
	"os/user"
	"runtime"
	"strings"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
)

const (
	Name = "Environment"
	URI  = "https://witness.testifysec.com/attestations/Environment/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, URI, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	OS        string            `json:"os"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	Variables map[string]string `json:"variables,omitempty"`
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) URI() string {
	return URI
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.OS = runtime.GOOS
	a.Variables = make(map[string]string)

	if hostname, err := os.Hostname(); err == nil {
		a.Hostname = hostname
	}

	if user, err := user.Current(); err == nil {
		a.Username = user.Username
	}

	variables := os.Environ()
	for _, v := range variables {
		parts := strings.SplitN(v, "=", 2)
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		a.Variables[key] = val
	}

	return nil
}
