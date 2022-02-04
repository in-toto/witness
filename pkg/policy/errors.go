// Copyright 2022 The Witness Contributors
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

package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

type ErrNoAttestations string

func (e ErrNoAttestations) Error() string {
	return fmt.Sprintf("no attestations found for step %v", string(e))
}

type ErrMissingAttestation struct {
	Step        string
	Attestation string
}

func (e ErrMissingAttestation) Error() string {
	return fmt.Sprintf("missing attestation in collection for step %v: %v", e.Step, e.Attestation)
}

type ErrPolicyExpired time.Time

func (e ErrPolicyExpired) Error() string {
	return fmt.Sprintf("policy expired on %v", time.Time(e))
}

type ErrKeyIDMismatch struct {
	Expected string
	Actual   string
}

func (e ErrKeyIDMismatch) Error() string {
	return fmt.Sprintf("public key in policy has expected key id %v but got %v", e.Expected, e.Actual)
}

type ErrUnknownStep string

func (e ErrUnknownStep) Error() string {
	return fmt.Sprintf("policy has no step named %v", string(e))
}

type ErrArtifactCycle string

func (e ErrArtifactCycle) Error() string {
	return fmt.Sprintf("cycle detected in step's artifact dependencies: %v", string(e))
}

type ErrMismatchArtifact struct {
	Artifact cryptoutil.DigestSet
	Material cryptoutil.DigestSet
	Path     string
}

func (e ErrMismatchArtifact) Error() string {
	return fmt.Sprintf("mismatched digests for %v", e.Path)
}

type ErrRegoInvalidData struct {
	Path     string
	Expected string
	Actual   interface{}
}

func (e ErrRegoInvalidData) Error() string {
	return fmt.Sprintf("invalid data from rego at %v, expected %v but got %T", e.Path, e.Expected, e.Actual)
}

type ErrPolicyDenied struct {
	Reasons []string
}

func (e ErrPolicyDenied) Error() string {
	return fmt.Sprintf("policy was denied due to:\n%v", strings.Join(e.Reasons, "\n  -"))
}
