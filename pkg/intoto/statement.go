// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intoto

import (
	"encoding/json"

	"github.com/testifysec/witness/pkg/cryptoutil"
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

func NewStatement(predicateType string, predicate []byte, subjects map[string]cryptoutil.DigestSet) (Statement, error) {
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

func DigestSetToSubject(name string, ds cryptoutil.DigestSet) (Subject, error) {
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
