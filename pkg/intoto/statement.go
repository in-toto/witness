package intoto

import (
	"encoding/json"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
)

const StatementType = "https://in-toto.io/Statement/v0.1"
const PayloadType = "application/vnd.in-toto+json"

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

func NewStatement(predicateType string, predicate []byte, digestMap map[string]attestation.DigestMap) Statement {
	subjects := []Subject{}
	for subject, digest := range digestMap {
		subjects = append(subjects, Subject{
			Name:   subject,
			Digest: digest,
		})
	}

	statement := Statement{
		Type:          StatementType,
		PredicateType: predicateType,
		Subject:       subjects,
		Predicate:     predicate,
	}

	return statement
}
