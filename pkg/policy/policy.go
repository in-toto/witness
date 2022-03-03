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

type PublicKey struct {
	KeyID string `json:"keyid"`
	Key   []byte `json:"key"`
}

type VerifiedStatement struct {
	Verifiers []cryptoutil.Verifier
	Statement intoto.Statement
	Reference string
}

// PublicKeyVerifiers returns verifiers for each of the policy's embedded public keys grouped by the key's ID
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

// TrustBundles returns the policy's x509 roots and intermediates grouped by the root's ID
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

// Verify will evaluate a policy using verifiedStatements. All statement signatures must be verified prior to calling this function.
// policy.Verify does not verify signatures.
func (p Policy) Verify(verifiedStatements []VerifiedStatement) error {
	if time.Now().After(p.Expires) {
		return ErrPolicyExpired(p.Expires)
	}

	approvedCollectionsByStep, err := p.checkFunctionaries(verifiedStatements)
	if err != nil {
		return err
	}

	passedByStep := make(map[string][]attestation.Collection)
	for _, step := range p.Steps {
		stepResults := step.validateAttestations(approvedCollectionsByStep[step.Name])
		if !stepResults.HasPassed() {
			if !stepResults.HasErrors() {
				return ErrNoAttestations(step.Name)
			}

			return stepResults
		}

		passedByStep[step.Name] = append(passedByStep[step.Name], stepResults.Passed...)
	}

	return p.verifyArtifacts(passedByStep)
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
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

				if err := functionary.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
					log.Debugf("(policy) skipping verifier: verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
					continue
				}

				collectionsByStep[step.Name] = append(collectionsByStep[step.Name], collection)
			}

		}
	}

	return collectionsByStep, nil
}

// verifyArtifacts will check the artifacts (materials+products) of the step referred to by `ArtifactsFrom` against the
// materials of the original step.  This ensures file integrity between each step.
func (p Policy) verifyArtifacts(collectionsByStep map[string][]attestation.Collection) error {
	for _, step := range p.Steps {
		accepted := make([]attestation.Collection, 0)
		for _, collection := range collectionsByStep[step.Name] {
			if err := verifyCollectionArtifacts(step, collection, collectionsByStep); err == nil {
				accepted = append(accepted, collection)
			}
		}

		if len(accepted) <= 0 {
			return ErrNoAttestations(step.Name)
		}
	}

	return nil
}

func verifyCollectionArtifacts(step Step, collection attestation.Collection, collectionsByStep map[string][]attestation.Collection) error {
	mats := collection.Materials()
	for _, artifactsFrom := range step.ArtifactsFrom {
		accepted := make([]attestation.Collection, 0)
		for _, testCollection := range collectionsByStep[artifactsFrom] {
			if err := compareArtifacts(mats, testCollection.Artifacts()); err != nil {
				break
			}

			accepted = append(accepted, testCollection)
		}

		if len(accepted) <= 0 {
			return ErrNoAttestations(step.Name)
		}
	}

	return nil
}

func compareArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) error {
	for path, mat := range mats {
		art, ok := arts[path]
		if !ok {
			continue
		}

		if !mat.Equal(art) {
			return ErrMismatchArtifact{
				Artifact: art,
				Material: mat,
				Path:     path,
			}
		}
	}

	return nil
}
