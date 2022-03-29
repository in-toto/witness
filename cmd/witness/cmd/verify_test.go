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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/log"
	"github.com/testifysec/witness/pkg/policy"
)

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

	err = os.MkdirAll("/tmp/witness", 0755)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile("/tmp/witness/envelope.txt", jsonEnvelope, 0644)

	if err != nil {
		t.Error(err)
	}

	envelopes, err := loadEnvelopesFromDisk([]string{"/tmp/witness/envelope.txt"})
	if err != nil {
		t.Error(err)
	}

	if len(envelopes) != 1 {
		t.Errorf("expected 1 envelope, got %d", len(envelopes))
	}

	if string(envelopes[0].Payload) != string(testPayload) {
		t.Errorf("expected payload to be %s, got %s", string(testPayload), string(envelopes[0].Payload))
	}

	if envelopes[0].PayloadType != "text" {
		t.Errorf("expected payload type to be text, got %s", envelopes[0].PayloadType)
	}

	if len(envelopes[0].Signatures) != 0 {
		t.Errorf("expected 0 signatures, got %d", len(envelopes[0].Signatures))
	}

	err = os.RemoveAll("/tmp/witness")
	if err != nil {
		t.Error(err)
	}

}

func Test_RunVerifyKeyPair(t *testing.T) {
	logger := newLogger()
	log.SetLogger(logger)
	logger.SetLevel("DEBUG")
	policy, funcPriv := makepolicyRSAPub(t)
	signedPolicy, pub := signPolicy(t, policy)

	attestationDir := t.TempDir()
	workDir := t.TempDir()
	policyPath := filepath.Join(attestationDir, "signed-policy.json")
	if err := os.WriteFile(policyPath, signedPolicy, 0644); err != nil {
		t.Error(err)
	}

	policyPubPath := filepath.Join(attestationDir, "policy-pub.pem")
	if err := os.WriteFile(policyPubPath, pub, 0644); err != nil {
		t.Error(err)
	}

	funcPrivPath := filepath.Join(attestationDir, "func-priv.pem")
	if err := os.WriteFile(funcPrivPath, funcPriv, 0644); err != nil {
		t.Error(err)
	}

	keyOptions := options.KeyOptions{
		KeyPath: funcPrivPath,
	}

	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1CollPath := filepath.Join(attestationDir, "step01.json")
	s1RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workDir,
		Attestations: []string{},
		OutFilePath:  s1CollPath,
		StepName:     "step01",
		RekorServer:  "",
		Tracing:      false,
	}

	if err := runRun(s1RunOptions, step1Args); err != nil {
		t.Error(err)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2CollPath := filepath.Join(attestationDir, "step02.json")
	s2RunOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workDir,
		Attestations: []string{},
		OutFilePath:  s2CollPath,
		StepName:     "step02",
		RekorServer:  "",
		Tracing:      false,
	}

	if err := runRun(s2RunOptions, step2Args); err != nil {
		t.Error(err)
	}

	vo := options.VerifyOptions{
		KeyPath:              policyPubPath,
		AttestationFilePaths: []string{s1CollPath, s2CollPath},
		PolicyFilePath:       policyPath,
		ArtifactFilePath:     filepath.Join(workDir, "test.txt"),
		RekorServer:          "",
	}

	if err := runVerify(vo, []string{}); err != nil {
		t.Error(err)
	}
}

func signPolicy(t *testing.T, p []byte) (signedPolicy []byte, pub []byte) {
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

	root := policy.Root{}

	p := makepolicy(t, functionary, pk, root)
	return p, fpriv
}

func makepolicy(t *testing.T, functionary policy.Functionary, publicKey policy.PublicKey, root policy.Root) []byte {
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
		keyID := functionary.CertConstraint.Roots[0]
		p.Roots[keyID] = root
	}

	p.Steps = make(map[string]policy.Step)
	p.Steps[step01.Name] = step01
	p.Steps[step02.Name] = step02

	p.PublicKeys[publicKey.KeyID] = publicKey
	pb, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Error(err)
	}

	return pb
}
