package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
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
	PublicKeys map[string]PublicKey `json:"publickey,omitempty"`
	Steps      map[string]Step      `json:"steps"`
}

type Root struct {
	Certificate   []byte   `json:"certificate"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

type Step struct {
	Name          string        `json:"name"`
	Functionaries []Functionary `json:"functionaries"`
	Attestations  []Attestation `json:"attestation"`
}

type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string         `json:"publickeyid,omitempty"`
}

type Attestation struct {
	Type     string   `json:"predicate"`
	Policies []string `json:"policies"`
}

type CertConstraint struct {
	Roots []string `json:"roots"`
}

type PublicKey struct {
	KeyID string `json:"keyid"`
	Key   []byte `json:"key"`
}

func (p Policy) loadPublicKeys() (map[string]crypto.Verifier, error) {
	verifiers := make(map[string]crypto.Verifier, 0)
	for _, key := range p.PublicKeys {
		verifier, err := crypto.NewVerifierFromReader(bytes.NewReader(key.Key))
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
		found := make(map[string]struct{})
		for _, attestation := range collection.Attestations {
			found[attestation.Type] = struct{}{}
		}

		for _, expected := range s.Attestations {
			_, ok := found[expected.Type]
			if !ok {
				return ErrMissingAttestation{
					Step:        s.Name,
					Attestation: expected.Type,
				}
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

	collectionsByStep := make(map[string][]attestation.Collection)
	for _, r := range signedCollections {
		env, err := dsse.Decode(r)
		if err != nil {
			continue
		}

		if env.PayloadType != attestation.CollectionType {
			continue
		}

		collection := attestation.Collection{}
		if err := json.Unmarshal(env.Payload, &collection); err != nil {
			continue
		}

		step, ok := p.Steps[collection.Name]
		if !ok {
			continue
		}

		allowedPubKeys := make([]crypto.Verifier, 0)
		for _, functionary := range step.Functionaries {
			pubKey, ok := publicKeysByID[functionary.PublicKeyID]
			if ok {
				allowedPubKeys = append(allowedPubKeys, pubKey)
			}
		}

		if err := env.Verify(allowedPubKeys...); err != nil {
			continue
		}

		collectionsByStep[step.Name] = append(collectionsByStep[step.Name], collection)
	}

	return collectionsByStep, nil
}
