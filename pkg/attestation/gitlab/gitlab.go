package gitlab

import (
	"os"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/attestation/jwt"
)

const (
	Name    = "Gitlab"
	Type    = "https://witness.testifysec.com/attestations/Gitlab/v0.1"
	jwksUrl = "https://gitlab.com/-/jwks"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type ErrNotGitlab struct{}

func (e ErrNotGitlab) Error() string {
	return "not in a gitlab ci job"
}

type Attestor struct {
	JWT          *jwt.Attestor `json:"jwt,omitempty"`
	CIConfigPath string        `json:"ciconfigpath"`
	JobID        string        `json:"jobid"`
	JobImage     string        `json:"jobimage"`
	JobName      string        `json:"jobname"`
	JobStage     string        `json:"jobstage"`
	JobUrl       string        `json:"joburl"`
	PipelineID   string        `json:"pipelineid"`
	PipelineUrl  string        `json:"pipelineurl"`
	ProjectID    string        `json:"projectid"`
	ProjectUrl   string        `json:"projecturl"`
	RunnerID     string        `json:"runnerid"`
	CIHost       string        `json:"cihost"`
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if os.Getenv("GITLAB_CI") != "true" {
		return ErrNotGitlab{}
	}

	jwtString := os.Getenv("CI_JOB_JWT")
	if jwtString != "" {
		a.JWT = jwt.New(jwt.WithToken(jwtString), jwt.WithJWKSUrl(jwksUrl))
		if err := a.JWT.Attest(ctx); err != nil {
			return err
		}
	}

	a.CIConfigPath = os.Getenv("CI_CONFIG_PATH")
	a.JobID = os.Getenv("CI_JOB_ID")
	a.JobImage = os.Getenv("CI_JOB_IMAGE")
	a.JobName = os.Getenv("CI_JOB_NAME")
	a.JobStage = os.Getenv("CI_JOB_STAGE")
	a.JobUrl = os.Getenv("CI_JOB_URL")
	a.PipelineID = os.Getenv("CI_PIPELINE_ID")
	a.PipelineUrl = os.Getenv("CI_PIPELINE_URL")
	a.ProjectID = os.Getenv("CI_PROJECT_ID")
	a.ProjectUrl = os.Getenv("CI_PROJECT_URL")
	a.RunnerID = os.Getenv("CI_RUNNER_ID")
	a.CIHost = os.Getenv("CI_SERVER_HOST")
	return nil
}
