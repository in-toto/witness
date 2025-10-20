// Copyright 2024 The Witness Contributors
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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"

	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
)

// ArchivistaClienter defines what we need to retrieve policies from an Archivista instance
type ArchivistaClienter interface {
	Download(ctx context.Context, gitoid string) (dsse.Envelope, error)
	Store(ctx context.Context, env dsse.Envelope) (string, error)
	SearchGitoids(ctx context.Context, vars archivista.SearchGitoidVariables) ([]string, error)
}

// LoadPolicy attempts to load a policy from either a file or Archivista.
// It prefers to load from a file, if it fails, it tries to load from Archivista
func LoadPolicy(ctx context.Context, policy string, ac ArchivistaClienter) (dsse.Envelope, error) {
	policyEnvelope := dsse.Envelope{}

	filePolicy, err := os.Open(policy)
	if err != nil {
		log.Debug("failed to open policy file: ", policy)
		if ac == nil || reflect.ValueOf(ac).IsNil() {
			log.Debug("archivista client is nil; cannot fetch policy from archivista")
			return policyEnvelope, fmt.Errorf("failed to open file to sign: %w", err)
		} else {
			log.Debug("attempting to fetch policy " + policy + " from archivista")
			policyEnvelope, err = ac.Download(ctx, policy)
			if err != nil {
				return policyEnvelope, fmt.Errorf("failed to fetch policy from archivista: %w", err)
			}
			log.Debug("policy " + policy + " downloaded from archivista")
		}

	} else {
		defer func() {
			if err := filePolicy.Close(); err != nil {
				log.Errorf("failed to close policy file: %v", err)
			}
		}()

		decoder := json.NewDecoder(filePolicy)
		if err := decoder.Decode(&policyEnvelope); err != nil {
			return policyEnvelope, fmt.Errorf("could not unmarshal policy envelope: %w", err)
		}
	}

	return policyEnvelope, nil
}
