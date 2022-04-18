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

package witness

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"

	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/log"
	"github.com/testifysec/witness/pkg/policy"
)

func VerifySignature(r io.Reader, verifiers ...cryptoutil.Verifier) (dsse.Envelope, error) {
	decoder := json.NewDecoder(r)
	envelope := dsse.Envelope{}
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("failed to parse dsse envelope: %v", err)
	}

	_, err := envelope.Verify(dsse.WithVerifiers(verifiers))
	return envelope, err
}

type verifyOptions struct {
	policyEnvelope      dsse.Envelope
	policyVerifiers     []cryptoutil.Verifier
	collectionEnvelopes []CollectionEnvelope
}

type CollectionEnvelope struct {
	Envelope  dsse.Envelope
	Reference string
}

type VerifyOption func(*verifyOptions)

//VerifyWithPolicy verifies a dsse envelopes against a policy
func VerifyWithCollectionEnvelopes(collectionEnvelopes []CollectionEnvelope) VerifyOption {
	return func(vo *verifyOptions) {
		vo.collectionEnvelopes = collectionEnvelopes
	}
}

//VerifyE verifies a dsse envelopes against a policy and returns the envelopes on success
func Verify(policyEnvelope dsse.Envelope, policyVerifiers []cryptoutil.Verifier, opts ...VerifyOption) ([]CollectionEnvelope, error) {
	verifiedEnvelopes := make([]CollectionEnvelope, 0)

	vo := verifyOptions{
		policyEnvelope:  policyEnvelope,
		policyVerifiers: policyVerifiers,
	}

	for _, opt := range opts {
		opt(&vo)
	}

	if _, err := vo.policyEnvelope.Verify(dsse.WithVerifiers(vo.policyVerifiers)); err != nil {
		return nil, fmt.Errorf("could not verify policy: %w", err)
	}

	pol := policy.Policy{}
	if err := json.Unmarshal(vo.policyEnvelope.Payload, &pol); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy from envelope: %w", err)
	}

	pubKeysById, err := pol.PublicKeyVerifiers()
	if err != nil {
		return nil, fmt.Errorf("failed to get pulic keys from policy: %w", err)
	}

	pubkeys := make([]cryptoutil.Verifier, 0)
	for _, pubkey := range pubKeysById {
		pubkeys = append(pubkeys, pubkey)
	}

	trustBundlesById, err := pol.TrustBundles()
	if err != nil {
		return nil, fmt.Errorf("failed to load policy trust bundles: %w", err)
	}

	roots := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	for _, trustBundle := range trustBundlesById {
		roots = append(roots, trustBundle.Root)
		intermediates = append(intermediates, intermediates...)
	}

	verifiedStatements := make([]policy.VerifiedStatement, 0)
	for _, env := range vo.collectionEnvelopes {
		passedVerifiers, err := env.Envelope.Verify(dsse.WithVerifiers(pubkeys), dsse.WithRoots(roots), dsse.WithIntermediates(intermediates))
		if err != nil {
			log.Debugf("(verify) skipping envelope: couldn't verify enveloper's signature with the policy's verifiers: %+v", err)
			continue
		}

		statement := intoto.Statement{}
		if err := json.Unmarshal(env.Envelope.Payload, &statement); err != nil {
			log.Debugf("(verify) skipping envelope: couldn't unmarshal envelope payload into in-toto statement: %+v", err)
			continue
		}

		verifiedStatements = append(verifiedStatements, policy.VerifiedStatement{
			Statement: statement,
			Verifiers: passedVerifiers,
			Reference: env.Reference,
		})
	}

	err = pol.Verify(verifiedStatements)
	if err != nil {
		return nil, fmt.Errorf("failed to verify policy: %w", err)
	}

	for _, env := range vo.collectionEnvelopes {
		for _, statement := range verifiedStatements {
			if statement.Reference == env.Reference {
				verifiedEnvelopes = append(verifiedEnvelopes, CollectionEnvelope{
					Envelope:  env.Envelope,
					Reference: env.Reference,
				})
			}
		}
	}
	return verifiedEnvelopes, nil
}
