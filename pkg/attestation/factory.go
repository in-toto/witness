package attestation

import (
	"fmt"

	"gitlab.com/testifysec/witness-cli/pkg/run"
)

var (
	attestationsByName = map[string]AttestorFactory{}
	attestationsByUri  = map[string]AttestorFactory{}
)

type Attestor interface {
	Name() string
	URI() string
	Attest(run.Result) error
}

type AttestorFactory func() Attestor

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

func RegisterAttestation(name, uri string, factoryFunc AttestorFactory) {
	attestationsByName[name] = factoryFunc
	attestationsByUri[uri] = factoryFunc
}

func GetFactoryByURI(uri string) (AttestorFactory, bool) {
	factory, ok := attestationsByUri[uri]
	return factory, ok
}

func GetFactories(attestations []string) ([]AttestorFactory, error) {
	factories := make([]AttestorFactory, 0)
	for _, attestation := range attestations {
		factory, ok := attestationsByName[attestation]
		if ok {
			factories = append(factories, factory)
			continue
		}

		factory, ok = attestationsByUri[attestation]
		if ok {
			factories = append(factories, factory)
			continue
		}

		return nil, ErrAttestationNotFound(attestation)
	}

	return factories, nil
}

func AllNames() []string {
	names := make([]string, 0)
	for name := range attestationsByName {
		names = append(names, name)
	}

	return names
}

func AllURIs() []string {
	uris := make([]string, 0)
	for uri := range attestationsByUri {
		uris = append(uris, uri)
	}

	return uris
}
