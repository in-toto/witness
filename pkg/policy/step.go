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

	"github.com/testifysec/witness/pkg/attestation"
)

type Step struct {
	Name          string        `json:"name"`
	Functionaries []Functionary `json:"functionaries"`
	Attestations  []Attestation `json:"attestations"`
	ArtifactsFrom []string      `json:"artifactsFrom,omitempty"`
}

type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string         `json:"publickeyid,omitempty"`
}

type Attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []RegoPolicy `json:"regopolicies"`
}

type RegoPolicy struct {
	Module []byte `json:"module"`
	Name   string `json:"name"`
}

type CertConstraint struct {
	Roots []string `json:"roots"`
}

// StepResult contains information about the verified collections for each step.
// Passed contains the collections that passed any rego policies and all expected attestations exist.
// Rejected contains the rejected collections and the error that caused them to be rejected.
type StepResult struct {
	Step     string
	Passed   []attestation.Collection
	Rejected []RejectedCollection
}

func (r StepResult) HasErrors() bool {
	return len(r.Rejected) > 0
}

func (r StepResult) HasPassed() bool {
	return len(r.Passed) > 0
}

func (r StepResult) Error() string {
	errs := make([]string, len(r.Rejected))
	for i, reject := range r.Rejected {
		errs[i] = reject.Reason.Error()
	}

	return fmt.Sprintf("attestations for step %v could not be used due to:\n%v", r.Step, strings.Join(errs, "\n"))
}

type RejectedCollection struct {
	Collection attestation.Collection
	Reason     error
}

// validateAttestations will test each collection against to ensure the expected attestations
// appear in the collection as well as that any rego policies pass for the step.
func (s Step) validateAttestations(attestCollections []attestation.Collection) StepResult {
	result := StepResult{Step: s.Name}
	if len(attestCollections) <= 0 {
		return result
	}

	for _, collection := range attestCollections {
		found := make(map[string]attestation.Attestor)
		for _, attestation := range collection.Attestations {
			found[attestation.Type] = attestation.Attestation
		}

		passed := true
		for _, expected := range s.Attestations {
			attestor, ok := found[expected.Type]
			if !ok {
				result.Rejected = append(result.Rejected, RejectedCollection{
					Collection: collection,
					Reason: ErrMissingAttestation{
						Step:        s.Name,
						Attestation: expected.Type,
					},
				})

				passed = false
				break
			}

			if err := EvaluateRegoPolicy(attestor, expected.RegoPolicies); err != nil {
				result.Rejected = append(result.Rejected, RejectedCollection{
					Collection: collection,
					Reason:     err,
				})

				passed = false
				break
			}
		}

		if passed {
			result.Passed = append(result.Passed, collection)
		}
	}

	return result
}
