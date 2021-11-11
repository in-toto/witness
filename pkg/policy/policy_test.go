package policy

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	witcrypt "gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
)

func createTestKey() (witcrypt.Signer, witcrypt.Verifier, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	signer := witcrypt.NewRSASigner(privKey, crypto.SHA256)
	verifier := witcrypt.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
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
	signer, verifier, pubKeyPem, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
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
						Predicate: attestation.CommandRunURI,
					},
				},
			},
		},
	}

	step1Collection := attestation.NewCollection("step1", []attestation.Attestor{attestation.NewCommandRun()})
	step1CollectionJson, err := json.Marshal(&step1Collection)
	step1CollReader := bytes.NewReader(step1CollectionJson)
	env, err := dsse.Sign(attestation.CollectionDataType, step1CollReader, signer)
	require.NoError(t, err)
	encodedEnv, err := json.Marshal(&env)
	require.NoError(t, err)
	envReader := bytes.NewReader(encodedEnv)
	assert.NoError(t, policy.Verify([]io.Reader{envReader}))
}
