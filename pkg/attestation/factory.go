package attestation

import (
	"fmt"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

var (
	attestationsByName = map[string]AttestorFactory{}
	attestationsByType = map[string]AttestorFactory{}
)

type Attestor interface {
	Name() string
	Type() string
	Attest(ctx *AttestationContext) error
}

type Subjecter interface {
	Subjects() map[string]cryptoutil.DigestSet
}

type AttestorFactory func() Attestor

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

func RegisterAttestation(name, uri string, factoryFunc AttestorFactory) {
	attestationsByName[name] = factoryFunc
	attestationsByType[uri] = factoryFunc
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
