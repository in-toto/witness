package attestation

type Collection map[string]Attestor

const CollectionDataType = "https://witness.testifysec.com/AttestationCollection/v0.1"

func NewCollection(attestors []Attestor) Collection {
	collection := make(map[string]Attestor)
	for _, attestor := range attestors {
		collection[attestor.URI()] = attestor
	}

	return collection
}
