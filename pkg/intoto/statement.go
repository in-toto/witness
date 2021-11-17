package intoto

import (
	"encoding/json"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
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

func NewStatement(predicateType string, predicate []byte, subjects map[string]crypto.DigestSet) (Statement, error) {
	statement := Statement{
		Type:          StatementType,
		PredicateType: predicateType,
		Subject:       make([]Subject, 0),
		Predicate:     predicate,
	}

	for name, ds := range subjects {
		subj, err := DigestSetToSubject(name, ds)
		if err != nil {
			return statement, err
		}

		statement.Subject = append(statement.Subject, subj)
	}

	return statement, nil
}

func DigestSetToSubject(name string, ds crypto.DigestSet) (Subject, error) {
	subj := Subject{
		Name: name,
	}

	digestsByName, err := ds.ToNameMap()
	if err != nil {
		return subj, err
	}

	subj.Digest = digestsByName
	return subj, nil
}
