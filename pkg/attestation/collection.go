package attestation

import (
	"encoding/json"

	"github.com/testifysec/witness/pkg/crypto"
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

func (c *Collection) Subjects() map[string]crypto.DigestSet {
	allSubjects := make(map[string]crypto.DigestSet)
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
