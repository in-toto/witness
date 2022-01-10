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

package material

import (
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/file"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "material"
	Type    = "https://witness.testifysec.com/attestations/material/v0.1"
	RunType = attestation.MaterialRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Option func(*Attestor)

type Attestor struct {
	Materials map[string]cryptoutil.DigestSet `json:"materials"`
}

func (a Attestor) Name() string {
	return Name
}

func (a Attestor) Type() string {
	return Type
}

func (rc *Attestor) RunType() attestation.RunType {
	return RunType
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}
	for _, opt := range opts {
		opt(attestor)
	}

	return attestor
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	materials, err := file.RecordArtifacts(ctx.WorkingDir(), nil, ctx.Hashes(), map[string]struct{}{})
	if err != nil {
		return err
	}

	a.Materials = materials
	return nil
}

func (a *Attestor) GetMaterials() map[string]cryptoutil.DigestSet {
	return a.Materials
}
