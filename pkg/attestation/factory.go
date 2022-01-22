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
	"fmt"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

var (
	attestationsByName = map[string]AttestorFactory{}
	attestationsByType = map[string]AttestorFactory{}
	attestationsByRun  = map[string]AttestorFactory{}
)

type Attestor interface {
	Name() string
	Type() string
	RunType() RunType
	Attest(ctx *AttestationContext) error
}

type Subjecter interface {
	Subjects() map[string]cryptoutil.DigestSet
}

type Materialer interface {
	Materials() map[string]cryptoutil.DigestSet
}

type Producter interface {
	Products() map[string]Product
}

type AttestorFactory func() Attestor

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

func RegisterAttestation(name, uri string, run RunType, factoryFunc AttestorFactory) {
	attestationsByName[name] = factoryFunc
	attestationsByType[uri] = factoryFunc
	attestationsByRun[run.String()] = factoryFunc
}

func FactoryByType(uri string) (AttestorFactory, bool) {
	factory, ok := attestationsByType[uri]
	return factory, ok
}

func FactoryByName(name string) (AttestorFactory, bool) {
	factory, ok := attestationsByName[name]
	return factory, ok
}

func Attestors(nameOrTypes []string) ([]Attestor, error) {
	attestors := make([]Attestor, 0)
	for _, nameOrType := range nameOrTypes {
		factory, ok := FactoryByName(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		factory, ok = FactoryByType(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		return nil, ErrAttestationNotFound(nameOrType)
	}

	return attestors, nil
}
