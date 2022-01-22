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

package maven

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "maven"
	Type    = "https://witness.testifysec.com/attestations/maven/v0.1"
	RunType = attestation.PreRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	XMLName      xml.Name          `xml:"project" json:"-"`
	GroupId      string            `xml:"groupId" json:"groupid"`
	ArtifactId   string            `xml:"artifactId" json:"artifactid"`
	Version      string            `xml:"version" json:"version"`
	ProjectName  string            `xml:"name" json:"projectname"`
	Dependencies []MavenDependency `xml:"dependencies>dependency" json:"dependencies"`

	pomPath  string
	subjects map[string]cryptoutil.DigestSet
}

type MavenDependency struct {
	GroupId    string `xml:"groupId" json:"groupid"`
	ArtifactId string `xml:"artifactId" json:"artifactid"`
	Version    string `xml:"version" json:"version"`
	Scope      string `xml:"scope" json:"scope"`
}

type Option func(*Attestor)

func WithPom(path string) Option {
	return func(a *Attestor) {
		a.pomPath = path
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{
		pomPath:  "pom.xml",
		subjects: make(map[string]cryptoutil.DigestSet),
	}

	for _, opt := range opts {
		opt(attestor)
	}

	return attestor
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
	pomFile, err := os.Open(a.pomPath)
	if err != nil {
		return err
	}

	defer pomFile.Close()
	pomFileBytes, err := io.ReadAll(pomFile)
	if err != nil {
		return err
	}

	if err := xml.Unmarshal(pomFileBytes, &a); err != nil {
		return err
	}

	hashes := ctx.Hashes()
	projectSubject := fmt.Sprintf("project:%v/%v@%v", a.GroupId, a.ArtifactId, a.Version)
	projectDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(projectSubject), hashes)
	if err != nil {
		return err
	}

	a.subjects[projectSubject] = projectDigest
	for _, dep := range a.Dependencies {
		depSubject := fmt.Sprintf("dependency:%v/%v@%v", dep.GroupId, dep.ArtifactId, dep.Version)
		depDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(depSubject), hashes)
		if err != nil {
			return err
		}

		a.subjects[depSubject] = depDigest
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
