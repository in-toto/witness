// Copyright 2021 The Witness Contributors
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

package gitlab

import (
	"fmt"
	"os"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/jwt"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "gitlab"
	Type    = "https://witness.testifysec.com/attestations/gitlab/v0.1"
	RunType = attestation.PreRunType

	jwksUrl = "https://gitlab.com/-/jwks"
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
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

	subjects map[string]cryptoutil.DigestSet
}

func New() *Attestor {
	return &Attestor{
		subjects: make(map[string]cryptoutil.DigestSet),
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
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

	pipelineSubj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.PipelineUrl), ctx.Hashes())
	if err != nil {
		return err
	}

	a.subjects[fmt.Sprintf("pipelineurl:%v", a.PipelineUrl)] = pipelineSubj
	jobSubj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.JobUrl), ctx.Hashes())
	if err != nil {
		return err
	}

	a.subjects[fmt.Sprintf("joburl:%v", a.JobUrl)] = jobSubj
	projectSubj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProjectUrl), ctx.Hashes())
	if err != nil {
		return err
	}

	a.subjects[fmt.Sprintf("projecturl:%v", a.ProjectUrl)] = projectSubj
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
