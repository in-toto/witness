package attestation

import (
	"fmt"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
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
	Subjects() map[string]crypto.DigestSet
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

func GetFactoryByType(uri string) (AttestorFactory, bool) {
	factory, ok := attestationsByType[uri]
	return factory, ok
}

func GetFactoryByName(name string) (AttestorFactory, bool) {
	factory, ok := attestationsByName[name]
	return factory, ok
}

func GetAttestors(nameOrTypes []string) ([]Attestor, error) {
	attestors := make([]Attestor, 0)
	for _, nameOrType := range nameOrTypes {
		factory, ok := GetFactoryByName(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		factory, ok = GetFactoryByType(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		return nil, ErrAttestationNotFound(nameOrType)
	}

	return attestors, nil
}
