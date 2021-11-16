package intoto

import (
	"crypto"
	"encoding/json"
	"strings"
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

func NewStatement(predicateType string, predicate []byte, digestMap map[string]map[crypto.Hash]string) Statement {
	subjects := []Subject{}
	for subject, digests := range digestMap {
		digestMap := make(map[string]string)
		for alg, digest := range digests {
			digestMap[strings.ToLower(strings.ReplaceAll(alg.String(), "-", ""))] = digest
		}

		subjects = append(subjects, Subject{
			Name:   subject,
			Digest: digestMap,
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
