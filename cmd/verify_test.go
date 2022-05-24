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
	"encoding/json"
	"io/ioutil"
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

func Test_RunVerifyCA(t *testing.T) {
	ca, intermediates, leafcert, leafkey := fullChain(t)

	ko := options.KeyOptions{
		KeyPath: leafkey.Name(),
		IntermediatePaths: []string{
			intermediates[0].Name(),
		},
		CertPath: leafcert.Name(),
	}

	caBytes, err := ioutil.ReadFile(ca.Name())
	require.NoError(t, err)

	policy := makepolicyCA(t, caBytes)
	signedPolicy, pub := signPolicyRSA(t, policy)

	workingDir := t.TempDir()
	attestationDir := t.TempDir()

	err = os.WriteFile(filepath.Join(workingDir, "signed-policy.json"), signedPolicy, 0644)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "policy-pub.pem"), pub, 0644)
	if err != nil {
		t.Error(err)
	}

	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1RunOptions := options.RunOptions{
		KeyOptions:   ko,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  filepath.Join(attestationDir, "step01.json"),
		StepName:     "step01",
		RekorServer:  "",
		Tracing:      false,
	}

	err = runRun(s1RunOptions, step1Args)
	if err != nil {
		t.Error(err)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2RunOptions := options.RunOptions{
		KeyOptions:   ko,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  filepath.Join(attestationDir, "step02.json"),
		StepName:     "step02",
		RekorServer:  "",
		Tracing:      false,
	}

	err = runRun(s2RunOptions, step2Args)
	if err != nil {
		t.Error(err)
	}

	vo := options.VerifyOptions{
		KeyPath:              filepath.Join(workingDir, "policy-pub.pem"),
		AttestationFilePaths: []string{filepath.Join(attestationDir, "step01.json"), filepath.Join(attestationDir, "step02.json")},
		PolicyFilePath:       filepath.Join(workingDir, "signed-policy.json"),
		ArtifactFilePath:     filepath.Join(workingDir, "test.txt"),
		RekorServer:          "",

		EmailContstraints: []string{},
	}

	err = runVerify(vo, []string{})
	if err != nil {
		t.Error(err)
	}

}

func Test_loadEnvelopesFromDisk(t *testing.T) {
	testPayload := []byte("test")

	envelope := dsse.Envelope{
		Payload:     testPayload,
		PayloadType: "text",
		Signatures:  []dsse.Signature{},
	}

	jsonEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Error(err)
	}

	workingDir := t.TempDir()

	err = os.MkdirAll(workingDir, 0755)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "envelope.txt"), jsonEnvelope, 0644)

	if err != nil {
		t.Error(err)
	}

	envelopes, err := loadEnvelopesFromDisk([]string{filepath.Join(workingDir, "envelope.txt")})
	if err != nil {
		t.Error(err)
	}

	if len(envelopes) != 1 {
		t.Errorf("expected 1 envelope, got %d", len(envelopes))
	}

	if string(envelopes[0].Envelope.Payload) != string(testPayload) {
		t.Errorf("expected payload to be %s, got %s", string(testPayload), string(envelopes[0].Envelope.Payload))
	}

	if envelopes[0].Envelope.PayloadType != "text" {
		t.Errorf("expected payload type to be text, got %s", envelopes[0].Envelope.PayloadType)
	}

	if len(envelopes[0].Envelope.Signatures) != 0 {
		t.Errorf("expected 0 signatures, got %d", len(envelopes[0].Envelope.Signatures))
	}
}

func Test_RunVerifyKeyPair(t *testing.T) {
	policy, funcPriv := makepolicyRSAPub(t)
	signedPolicy, pub := signPolicyRSA(t, policy)

	workingDir := t.TempDir()
	attestationDir := t.TempDir()

	err := os.WriteFile(filepath.Join(workingDir, "signed-policy.json"), signedPolicy, 0644)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "policy-pub.pem"), pub, 0644)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "func-priv.pem"), funcPriv, 0644)
	if err != nil {
		t.Error(err)
	}

	keyOptions := options.KeyOptions{
		KeyPath: filepath.Join(workingDir, "func-priv.pem"),
	}

	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  filepath.Join(attestationDir, "step01.json"),
		StepName:     "step01",
		RekorServer:  "",
		Tracing:      false,
	}

	err = runRun(s1RunOptions, step1Args)
	if err != nil {
		t.Error(err)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  filepath.Join(attestationDir, "step02.json"),
		StepName:     "step02",
		RekorServer:  "",
		Tracing:      false,
	}

	err = runRun(s2RunOptions, step2Args)
	if err != nil {
		t.Error(err)
	}

	vo := options.VerifyOptions{
		KeyPath:              filepath.Join(workingDir, "policy-pub.pem"),
		AttestationFilePaths: []string{filepath.Join(attestationDir, "step01.json"), filepath.Join(attestationDir, "step02.json")},
		PolicyFilePath:       filepath.Join(workingDir, "signed-policy.json"),
		ArtifactFilePath:     filepath.Join(workingDir, "test.txt"),
		RekorServer:          "",
	}

	err = runVerify(vo, []string{})
	if err != nil {
		t.Error(err)
	}

}

func signPolicyRSA(t *testing.T, p []byte) (signedPolicy []byte, pub []byte) {
	sign, _, pub, _, err := createTestRSAKey()
	if err != nil {
		t.Error(err)
	}

	reader := bytes.NewReader(p)
	outBytes := []byte{}

	writer := bytes.NewBuffer(outBytes)

	err = witness.Sign(reader, "https://witness.testifysec.com/policy/v0.1", writer, sign)
	if err != nil {
		t.Error(err)
	}

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
	if err != nil {
		t.Error(err)
	}

	keyID, err := ver.KeyID()
	if err != nil {
		t.Error(err)
	}

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
	if err != nil {
		t.Error(err)
	}

	return pb
}
