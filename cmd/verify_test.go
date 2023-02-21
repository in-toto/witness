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

package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	witness "github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/attestation/commandrun"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/policy"
	"github.com/testifysec/witness/options"
)

func TestRunVerifyCA(t *testing.T) {
	ca, intermediates, leafcert, leafkey := fullChain(t)

	ko := options.KeyOptions{
		KeyPath: leafkey.Name(),
		IntermediatePaths: []string{
			intermediates[0].Name(),
		},
		CertPath: leafcert.Name(),
	}

	caBytes, err := os.ReadFile(ca.Name())
	require.NoError(t, err)

	policy := makepolicyCA(t, caBytes)
	signedPolicy, pub := signPolicyRSA(t, policy)

	workingDir := t.TempDir()
	attestationDir := t.TempDir()

	policyFilePath := filepath.Join(workingDir, "signed-policy.json")
	require.NoError(t, os.WriteFile(policyFilePath, signedPolicy, 0644))

	policyPubFilePath := filepath.Join(workingDir, "policy-pub.pem")
	require.NoError(t, os.WriteFile(policyPubFilePath, pub, 0644))

	artifactPath := filepath.Join(workingDir, "test.txt")
	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1FilePath := filepath.Join(attestationDir, "step01.json")
	s1RunOptions := options.RunOptions{
		KeyOptions:   ko,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  s1FilePath,
		StepName:     "step01",
		Tracing:      false,
	}

	require.NoError(t, runRun(context.Background(), s1RunOptions, step1Args))

	subjects := []string{}
	artifactDigest, err := cryptoutil.CalculateDigestSetFromFile(artifactPath, []crypto.Hash{crypto.SHA256})
	require.NoError(t, err)

	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2FilePath := filepath.Join(attestationDir, "step02.json")
	s2RunOptions := options.RunOptions{
		KeyOptions:   ko,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  s2FilePath,
		StepName:     "step02",
		Tracing:      false,
	}

	require.NoError(t, runRun(context.Background(), s2RunOptions, step2Args))

	vo := options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		ArtifactFilePath:     artifactPath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))

	// test that verify works without artifactfilepath but the subject of the modified articact also provided
	artifactDigest, err = cryptoutil.CalculateDigestSetFromFile(artifactPath, []crypto.Hash{crypto.SHA256})
	require.NoError(t, err)
	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	vo = options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))
}

func TestRunVerifyKeyPair(t *testing.T) {
	policy, funcPriv := makepolicyRSAPub(t)
	signedPolicy, pub := signPolicyRSA(t, policy)
	workingDir := t.TempDir()
	attestationDir := t.TempDir()
	policyFilePath := filepath.Join(workingDir, "signed-policy.json")
	require.NoError(t, os.WriteFile(policyFilePath, signedPolicy, 0644))

	policyPubFilePath := filepath.Join(workingDir, "policy-pub.pem")
	require.NoError(t, os.WriteFile(policyPubFilePath, pub, 0644))

	funcPrivFilepath := filepath.Join(workingDir, "func-priv.pem")
	require.NoError(t, os.WriteFile(funcPrivFilepath, funcPriv, 0644))

	keyOptions := options.KeyOptions{
		KeyPath: funcPrivFilepath,
	}

	artifactPath := filepath.Join(workingDir, "test.txt")
	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1FilePath := filepath.Join(attestationDir, "step01.json")
	s1RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  s1FilePath,
		StepName:     "step01",
		Tracing:      false,
	}

	require.NoError(t, runRun(context.Background(), s1RunOptions, step1Args))

	subjects := []string{}
	artifactDigest, err := cryptoutil.CalculateDigestSetFromFile(artifactPath, []crypto.Hash{crypto.SHA256})
	require.NoError(t, err)

	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2FilePath := filepath.Join(attestationDir, "step02.json")
	s2RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  s2FilePath,
		StepName:     "step02",
		Tracing:      false,
	}

	require.NoError(t, runRun(context.Background(), s2RunOptions, step2Args))

	vo := options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		ArtifactFilePath:     artifactPath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))

	// test that verify works without artifactfilepath but the subject of the modified articact also provided
	artifactDigest, err = cryptoutil.CalculateDigestSetFromFile(artifactPath, []crypto.Hash{crypto.SHA256})
	require.NoError(t, err)
	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	vo = options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))
}

func signPolicyRSA(t *testing.T, p []byte) (signedPolicy []byte, pub []byte) {
	sign, _, pub, _, err := createTestRSAKey()
	require.NoError(t, err)
	reader := bytes.NewReader(p)
	outBytes := []byte{}
	writer := bytes.NewBuffer(outBytes)
	require.NoError(t, witness.Sign(reader, "https://witness.testifysec.com/policy/v0.1", writer, dsse.SignWithSigners(sign)))
	return writer.Bytes(), pub
}

func makepolicyCA(t *testing.T, ca []byte) []byte {
	r := bytes.NewReader(ca)
	verifier, err := cryptoutil.NewVerifierFromReader(r)
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	functionary := policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			CommonName:    "*",
			DNSNames:      []string{"*"},
			Emails:        []string{"*"},
			Organizations: []string{"*"},
			URIs:          []string{"*"},
			Roots:         []string{keyID},
		},
	}

	root := policy.Root{
		Certificate: ca,
	}

	roots := map[string]policy.Root{}
	roots[keyID] = root
	policy := makepolicy(t, functionary, policy.PublicKey{}, roots)
	return policy
}

func makepolicyRSAPub(t *testing.T) ([]byte, []byte) {
	_, ver, pub, fpriv, err := createTestRSAKey()
	require.NoError(t, err)
	keyID, err := ver.KeyID()
	require.NoError(t, err)
	functionary := policy.Functionary{
		Type:        "PublicKey",
		PublicKeyID: keyID,
	}

	pk := policy.PublicKey{
		KeyID: keyID,
		Key:   pub,
	}

	p := makepolicy(t, functionary, pk, nil)
	return p, fpriv
}

func makepolicy(t *testing.T, functionary policy.Functionary, publicKey policy.PublicKey, roots map[string]policy.Root) []byte {
	step01 := policy.Step{
		Name:          "step01",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
	}

	step02 := policy.Step{
		Name:          "step02",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
		ArtifactsFrom: []string{"step01"},
	}

	p := policy.Policy{
		Expires:    time.Now().Add(1 * time.Hour),
		PublicKeys: map[string]policy.PublicKey{},
		Steps:      map[string]policy.Step{},
	}

	if functionary.CertConstraint.Roots != nil {
		p.Roots = roots
	}

	p.Steps = make(map[string]policy.Step)
	p.Steps[step01.Name] = step01
	p.Steps[step02.Name] = step02

	if publicKey.KeyID != "" {

		p.PublicKeys[publicKey.KeyID] = publicKey

	}

	pb, err := json.MarshalIndent(p, "", "  ")
	require.NoError(t, err)
	return pb
}
