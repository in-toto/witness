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
	"testing"
	"time"

	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/dsse"
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

	workingDir := t.TempDir()

	err = os.MkdirAll(workingDir, 0755)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(workingDir+"envelope.txt", jsonEnvelope, 0644)

	if err != nil {
		t.Error(err)
	}

	envelopes, err := loadEnvelopesFromDisk([]string{workingDir + "envelope.txt"})
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
	policy, funcPriv := makepolicyRSAPub(t)
	signedPolicy, pub := signPolicy(t, policy)

	workingDir := t.TempDir()
	attestationDir := t.TempDir()

	err := os.WriteFile(workingDir+"signed-policy.json", signedPolicy, 0644)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(workingDir+"policy-pub.pem", pub, 0644)
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile(workingDir+"func-priv.pem", funcPriv, 0644)
	if err != nil {
		t.Error(err)
	}

	keyOptions := options.KeyOptions{
		KeyPath: workingDir + "func-priv.pem",
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
		OutFilePath:  attestationDir + "step01.json",
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
		OutFilePath:  attestationDir + "step02.json",
		StepName:     "step02",
		RekorServer:  "",
		Tracing:      false,
	}

	err = runRun(s2RunOptions, step2Args)
	if err != nil {
		t.Error(err)
	}

	vo := options.VerifyOptions{
		KeyPath:              workingDir + "policy-pub.pem",
		AttestationFilePaths: []string{attestationDir + "step01.json", attestationDir + "step02.json"},
		PolicyFilePath:       workingDir + "signed-policy.json",
		ArtifactFilePath:     workingDir + "test.txt",
		RekorServer:          "",
	}

	err = runVerify(vo, []string{})
	if err != nil {
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
