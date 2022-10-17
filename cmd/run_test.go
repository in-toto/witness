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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/witness/options"
)

func TestRunRSAKeyPair(t *testing.T) {
	priv, _ := rsakeypair(t)
	keyOptions := options.KeyOptions{
		KeyPath: priv.Name(),
	}

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  attestationPath,
		StepName:     "teststep",
		Tracing:      false,
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	err := runRun(context.Background(), runOptions, args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Error(err)
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(attestationBytes, &env); err != nil {
		t.Error(err)
	}
}

func Test_runRunRSACA(t *testing.T) {
	_, intermediates, leafcert, leafkey := fullChain(t)
	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	intermediateNames := []string{}
	for _, intermediate := range intermediates {
		intermediateNames = append(intermediateNames, intermediate.Name())
	}

	keyOptions := options.KeyOptions{
		KeyPath:           leafkey.Name(),
		CertPath:          leafcert.Name(),
		IntermediatePaths: intermediateNames,
		SpiffePath:        "",
	}

	runOptions := options.RunOptions{
		KeyOptions:   keyOptions,
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  attestationPath,
		StepName:     "teststep",
		Tracing:      false,
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	err := runRun(context.Background(), runOptions, args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Error(err)
	}

	if len(attestationBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

	env := dsse.Envelope{}
	if err := json.Unmarshal(attestationBytes, &env); err != nil {
		t.Errorf("Error reading envelope: %v", err)
	}

	b, err := os.ReadFile(intermediateNames[0])
	if err != nil {
		t.Errorf("Error reading intermediate cert: %v", err)
	}

	if !bytes.Equal(b, env.Signatures[0].Intermediates[0]) {
		t.Errorf("Intermediates do not match")
	}

	b, err = os.ReadFile(leafcert.Name())
	if err != nil {
		t.Errorf("Error reading leaf cert: %v", err)
	}

	if !bytes.Equal(b, env.Signatures[0].Certificate) {
		t.Errorf("Leaf cert does not match")
	}

}

func createTestRSAKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return signer, verifier, pemBytes, privKeyBytes, nil
}
