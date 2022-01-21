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
	"time"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/log"
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

type VerifiedStatement struct {
	Verifiers []cryptoutil.Verifier
	Statement intoto.Statement
}

func (p Policy) PublicKeyVerifiers() (map[string]cryptoutil.Verifier, error) {
	verifiers := make(map[string]cryptoutil.Verifier)
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

type TrustBundle struct {
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
}

func (p Policy) TrustBundles() (map[string]TrustBundle, error) {
	bundles := make(map[string]TrustBundle)
	for id, root := range p.Roots {
		bundle := TrustBundle{}
		var err error
		bundle.Root, err = parseCertificate(root.Certificate)
		if err != nil {
			return bundles, err
		}

		for _, intBytes := range root.Intermediates {
			cert, err := parseCertificate(intBytes)
			if err != nil {
				return bundles, err
			}

			bundle.Intermediates = append(bundle.Intermediates, cert)
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

func (p Policy) Verify(verifiedStatements []VerifiedStatement) error {
	if time.Now().After(p.Expires) {
		return ErrPolicyExpired(p.Expires)
	}

	approvedCollectionsByStep, err := p.checkFunctionaries(verifiedStatements)
	if err != nil {
		return err
	}

	for _, step := range p.Steps {
		if err := step.Verify(approvedCollectionsByStep[step.Name]); err != nil {
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

func (p Policy) checkFunctionaries(verifiedStatements []VerifiedStatement) (map[string][]attestation.Collection, error) {
	trustBundles, err := p.TrustBundles()
	if err != nil {
		return nil, err
	}

	collectionsByStep := make(map[string][]attestation.Collection)
	for _, verifiedStatement := range verifiedStatements {
		if verifiedStatement.Statement.PredicateType != attestation.CollectionType {
			log.Debugf("(policy) skipping statement: predicate type is not a collection (%v)", verifiedStatement.Statement.PredicateType)
			continue
		}

		collection := attestation.Collection{}
		if err := json.Unmarshal(verifiedStatement.Statement.Predicate, &collection); err != nil {
			log.Debugf("(policy) skipping statement: could not unmarshal predicate as a collection: %f", err)
			continue
		}

		step, ok := p.Steps[collection.Name]
		if !ok {
			log.Debugf("(policy) skipping statement: collection's name is not a step in the policy (%v)", collection.Name)
			continue
		}

		for _, verifier := range verifiedStatement.Verifiers {
			verifierID, err := verifier.KeyID()
			if err != nil {
				log.Debugf("(policy) skipping verifier: could not get key id: %v", err)
				continue
			}

		outerLoop:
			for _, functionary := range step.Functionaries {
				if functionary.PublicKeyID != "" && functionary.PublicKeyID == verifierID {
					collectionsByStep[step.Name] = append(collectionsByStep[collection.Name], collection)
					break
				}

				x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
				if !ok {
					log.Debugf("(policy) skipping verifier: verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
					continue
				}

				if len(functionary.CertConstraint.Roots) == 0 {
					log.Debugf("(policy) skipping verifier: verifier with ID %v is an x509 verifier, but step %v does not have any truested roots", verifierID, step)
					continue
				}

				for _, rootID := range functionary.CertConstraint.Roots {
					bundle, ok := trustBundles[rootID]
					if !ok {
						log.Debugf("(policy) skipping verifier: could not get trust bundle for step %v and root ID %v", step, rootID)
						continue
					}

					if err := x509Verifier.BelongsToRoot(bundle.Root); err == nil {
						collectionsByStep[step.Name] = append(collectionsByStep[step.Name], collection)
						break outerLoop
					}
				}
			}
		}

	}

	return collectionsByStep, nil
}
