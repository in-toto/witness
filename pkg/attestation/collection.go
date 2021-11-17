package attestation

import (
	"encoding/json"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

type Collection struct {
	Name         string              `json:"name"`
	Attestations map[string]Attestor `json:"attestations"`
}

const CollectionDataType = "https://witness.testifysec.com/AttestationCollection/v0.1"

func NewCollection(name string, attestors []Attestor) Collection {
	collection := Collection{
		Name:         name,
		Attestations: make(map[string]Attestor),
	}
	for _, attestor := range attestors {
		collection.Attestations[attestor.URI()] = attestor
	}

	return collection
}

func (c *Collection) UnmarshalJSON(data []byte) error {
	rawMsg := struct {
		Name         string
		Attestations map[string]json.RawMessage
	}{}

	if err := json.Unmarshal(data, &rawMsg); err != nil {
		return err
	}

	c.Name = rawMsg.Name
	c.Attestations = make(map[string]Attestor)
	for uri, attest := range rawMsg.Attestations {
		factory, ok := GetFactoryByURI(uri)
		if !ok {
			return ErrAttestationNotFound(uri)
		}

		newAttest := factory()
		if err := json.Unmarshal(attest, &newAttest); err != nil {
			return err
		}

		c.Attestations[uri] = newAttest
	}

	return nil
}

func (c *Collection) Subjects() map[string]crypto.DigestSet {
	allSubjects := make(map[string]crypto.DigestSet)
	for _, attestor := range c.Attestations {
		if subjecter, ok := attestor.(Subjecter); ok {
			subjects := subjecter.Subjects()
			for subject, digest := range subjects {
				allSubjects[subject] = digest
			}
		}
	}

	return allSubjects
}
