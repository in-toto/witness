package attestation

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
