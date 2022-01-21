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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/intoto"
)

func createTestKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return nil, nil, nil, err
	}

	return signer, verifier, pemBytes, nil
}

func TestVerify(t *testing.T) {
	_, verifier, pubKeyPem, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	commandPolicy := []byte(`package test
deny[msg] {
	input.cmd != ["go", "build", "./"]
	msg := "unexpected cmd"
}`)
	exitPolicy := []byte(`package commandrun.exitcode
deny[msg] {
	input.exitcode != 0
	msg := "exitcode not 0"
}`)

	policy := Policy{
		Expires: time.Now().Add(1 * time.Hour),
		PublicKeys: map[string]PublicKey{
			keyID: {
				KeyID: keyID,
				Key:   pubKeyPem,
			},
		},
		Steps: map[string]Step{
			"step1": {
				Name: "step1",
				Functionaries: []Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID,
					},
				},
				Attestations: []Attestation{
					{
						Type: commandrun.Type,
						RegoPolicies: []RegoPolicy{
							{
								Module: commandPolicy,
								Name:   "expected command",
							},
							{
								Name:   "exited successfully",
								Module: exitPolicy,
							},
						},
					},
				},
			},
		},
	}

	commandRun := commandrun.New()
	commandRun.Cmd = []string{"go", "build", "./"}
	commandRun.ExitCode = 0
	step1Collection := attestation.NewCollection("step1", []attestation.Attestor{commandRun})
	step1CollectionJson, err := json.Marshal(&step1Collection)
	require.NoError(t, err)
	intotoStatement, err := intoto.NewStatement(attestation.CollectionType, step1CollectionJson, map[string]cryptoutil.DigestSet{})
	require.NoError(t, err)
	assert.NoError(t, policy.Verify([]VerifiedStatement{
		{
			Verifiers: []cryptoutil.Verifier{verifier},
			Statement: intotoStatement,
		},
	}))
	assert.Error(t, policy.Verify([]VerifiedStatement{
		{
			Statement: intotoStatement,
		},
	}))
}
