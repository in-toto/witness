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

package policy

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/intoto"
)

const PolicyPredicate = "https://witness.testifysec.com/policy/v0.1"

type ErrNoAttestations string

func (e ErrNoAttestations) Error() string {
	return fmt.Sprintf("no attestations found for step %v", string(e))
}

type ErrMissingAttestation struct {
	Step        string
	Attestation string
}

func (e ErrMissingAttestation) Error() string {
	return fmt.Sprintf("missing attestation in collection for step %v: %v", e.Step, e.Attestation)
}

type ErrPolicyExpired time.Time

func (e ErrPolicyExpired) Error() string {
	return fmt.Sprintf("policy expired on %v", time.Time(e))
}

type ErrKeyIDMismatch struct {
	Expected string
	Actual   string
}

func (e ErrKeyIDMismatch) Error() string {
	return fmt.Sprintf("public key in policy has expected key id %v but got %v", e.Expected, e.Actual)
}

type Policy struct {
	Expires    time.Time            `json:"expires"`
	Roots      map[string]Root      `json:"roots,omitempty"`
	PublicKeys map[string]PublicKey `json:"publickeys,omitempty"`
	Steps      map[string]Step      `json:"steps"`
}

type Root struct {
	Certificate   []byte   `json:"certificate"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

type Step struct {
	Name          string        `json:"name"`
	Functionaries []Functionary `json:"functionaries"`
	Attestations  []Attestation `json:"attestations"`
}

type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string         `json:"publickeyid,omitempty"`
}

type Attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []RegoPolicy `json:"regopolicies"`
}

type RegoPolicy struct {
	Module []byte `json:"module"`
	Name   string `json:"name"`
}

type CertConstraint struct {
	Roots []string `json:"roots"`
}

type PublicKey struct {
	KeyID string `json:"keyid"`
	Key   []byte `json:"key"`
}

func (p Policy) loadPublicKeys() (map[string]cryptoutil.Verifier, error) {
	verifiers := make(map[string]cryptoutil.Verifier, 0)
	for _, key := range p.PublicKeys {
		verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(key.Key))
		if err != nil {
			return nil, err
		}

		keyID, err := verifier.KeyID()
		if err != nil {
			return nil, err
		}

		if keyID != key.KeyID {
			return nil, ErrKeyIDMismatch{
				Expected: key.KeyID,
				Actual:   keyID,
			}
		}

		verifiers[keyID] = verifier
	}

	return verifiers, nil
}

type trustBundle struct {
	root          *x509.Certificate
	intermediates []*x509.Certificate
}

func (p Policy) loadRoots() (map[string]trustBundle, error) {
	bundles := make(map[string]trustBundle)
	for id, root := range p.Roots {
		bundle := trustBundle{}
		var err error
		bundle.root, err = parseCertificate(root.Certificate)
		if err != nil {
			return bundles, err
		}

		for _, intBytes := range root.Intermediates {
			cert, err := parseCertificate(intBytes)
			if err != nil {
				return bundles, err
			}

			bundle.intermediates = append(bundle.intermediates, cert)
		}

		bundles[id] = bundle
	}

	return bundles, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	possibleCert, err := cryptoutil.TryParseKeyFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	cert, ok := possibleCert.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("value is not an x509 certificate")
	}

	return cert, nil
}

func (p Policy) Verify(signedCollections []io.Reader) error {
	if time.Now().After(p.Expires) {
		return ErrPolicyExpired(p.Expires)
	}

	collectionsByStep, err := p.verifyCollections(signedCollections)
	if err != nil {
		return err
	}

	for _, step := range p.Steps {
		if err := step.Verify(collectionsByStep[step.Name]); err != nil {
			return err
		}
	}

	return nil
}

func (s Step) Verify(attestCollections []attestation.Collection) error {
	if len(attestCollections) <= 0 {
		return ErrNoAttestations(s.Name)
	}

	for _, collection := range attestCollections {
		found := make(map[string]attestation.Attestor)
		for _, attestation := range collection.Attestations {
			found[attestation.Type] = attestation.Attestation
		}

		for _, expected := range s.Attestations {
			attestor, ok := found[expected.Type]
			if !ok {
				return ErrMissingAttestation{
					Step:        s.Name,
					Attestation: expected.Type,
				}
			}

			if err := EvaluateRegoPolicy(attestor, expected.RegoPolicies); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p Policy) verifyCollections(signedCollections []io.Reader) (map[string][]attestation.Collection, error) {
	publicKeysByID, err := p.loadPublicKeys()
	if err != nil {
		return nil, err
	}

	trustBundles, err := p.loadRoots()
	if err != nil {
		return nil, err
	}

	collectionsByStep := make(map[string][]attestation.Collection)
	for _, r := range signedCollections {
		env, err := dsse.Decode(r)
		if err != nil {
			continue
		}

		if env.PayloadType != intoto.PayloadType {
			continue
		}

		statement := intoto.Statement{}
		if err := json.Unmarshal(env.Payload, &statement); err != nil {
			continue
		}

		if statement.PredicateType != attestation.CollectionType {
			continue
		}

		collection := attestation.Collection{}
		if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
			continue
		}

		step, ok := p.Steps[collection.Name]
		if !ok {
			continue
		}

		functionaries := make([]cryptoutil.Verifier, 0)
		for _, functionary := range step.Functionaries {
			if functionary.PublicKeyID != "" {
				pubKey, ok := publicKeysByID[functionary.PublicKeyID]
				if ok {
					functionaries = append(functionaries, pubKey)
					continue
				}
			}

			for _, root := range functionary.CertConstraint.Roots {
				bundle, ok := trustBundles[root]
				if !ok {
					continue
				}

				for _, sig := range env.Signatures {
					if len(sig.Certificate) == 0 {
						continue
					}

					cert, err := parseCertificate(sig.Certificate)
					if err != nil {
						continue
					}

					intermediates := make([]*x509.Certificate, 0, len(bundle.intermediates))
					copy(intermediates, bundle.intermediates)
					for _, intBytes := range sig.Intermediates {
						intermediate, err := parseCertificate(intBytes)
						if err != nil {
							continue
						}

						intermediates = append(intermediates, intermediate)
					}

					verifier, err := cryptoutil.NewX509Verifier(cert, intermediates, []*x509.Certificate{bundle.root})
					if err != nil {
						continue
					}

					functionaries = append(functionaries, verifier)
				}
			}
		}

		if err := env.Verify(functionaries...); err != nil {
			fmt.Printf("didn't verify %v\n", err)
			continue
		}

		collectionsByStep[step.Name] = append(collectionsByStep[step.Name], collection)
	}

	return collectionsByStep, nil
}
