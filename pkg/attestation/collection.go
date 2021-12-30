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

package attestation

import (
	"encoding/json"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

const CollectionType = "https://witness.testifysec.com/AttestationCollection/v0.1"

type Collection struct {
	Name         string                  `json:"name"`
	Attestations []CollectionAttestation `json:"attestations"`
}

type CollectionAttestation struct {
	Type        string   `json:"type"`
	Attestation Attestor `json:"attestation"`
}

func NewCollection(name string, attestors []Attestor) Collection {
	collection := Collection{
		Name:         name,
		Attestations: make([]CollectionAttestation, 0),
	}

	for _, attestor := range attestors {
		collection.Attestations = append(collection.Attestations, NewCollectionAttestation(attestor))
	}

	return collection
}

func NewCollectionAttestation(attestor Attestor) CollectionAttestation {
	return CollectionAttestation{
		Type:        attestor.Type(),
		Attestation: attestor,
	}
}

func (c *CollectionAttestation) UnmarshalJSON(data []byte) error {
	proposed := struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	}{}

	if err := json.Unmarshal(data, &proposed); err != nil {
		return err
	}

	factory, ok := FactoryByType(proposed.Type)
	if !ok {
		return ErrAttestationNotFound(proposed.Type)
	}

	newAttest := factory()
	if err := json.Unmarshal(proposed.Attestation, &newAttest); err != nil {
		return err
	}

	c.Type = proposed.Type
	c.Attestation = newAttest
	return nil
}

func (c *Collection) Subjects() map[string]cryptoutil.DigestSet {
	allSubjects := make(map[string]cryptoutil.DigestSet)
	for _, collectionAttestation := range c.Attestations {
		if subjecter, ok := collectionAttestation.Attestation.(Subjecter); ok {
			subjects := subjecter.Subjects()
			for subject, digest := range subjects {
				allSubjects[subject] = digest
			}
		}
	}

	return allSubjects
}
