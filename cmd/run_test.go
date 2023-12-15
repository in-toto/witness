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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/signer"
	"github.com/testifysec/go-witness/signer/file"
)

func TestRunRSAKeyPair(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
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

	require.NoError(t, runRun(context.Background(), runOptions, args, signer))
	attestationBytes, err := os.ReadFile(attestationPath)
	require.NoError(t, err)
	env := dsse.Envelope{}
	require.NoError(t, json.Unmarshal(attestationBytes, &env))
}

func Test_runRunRSACA(t *testing.T) {
	_, intermediates, leafcert, leafkey := fullChain(t)
	signerOptions := options.SignerOptions{}
	signerOptions["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
		func(sp signer.SignerProvider) (signer.SignerProvider, error) {
			fsp := sp.(file.FileSignerProvider)
			fsp.KeyPath = leafkey.Name()
			fsp.IntermediatePaths = []string{intermediates[0].Name()}
			for _, intermediate := range intermediates {
				fsp.IntermediatePaths = append(fsp.IntermediatePaths, intermediate.Name())
			}

			fsp.CertPath = leafcert.Name()
			return fsp, nil
		},
	}

	signers, err := loadSigners(context.Background(), signerOptions, map[string]struct{}{"file": {}})
	require.NoError(t, err)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
		SignerOptions: signerOptions,
		WorkingDir:    workingDir,
		Attestations:  []string{},
		OutFilePath:   attestationPath,
		StepName:      "teststep",
		Tracing:       false,
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	require.NoError(t, runRun(context.Background(), runOptions, args, signers...))
	attestationBytes, err := os.ReadFile(attestationPath)
	require.NoError(t, err)
	assert.True(t, len(attestationBytes) > 0)

	env := dsse.Envelope{}
	if err := json.Unmarshal(attestationBytes, &env); err != nil {
		t.Errorf("Error reading envelope: %v", err)
	}

	b, err := os.ReadFile(intermediates[0].Name())
	require.NoError(t, err)
	assert.Equal(t, b, env.Signatures[0].Intermediates[0])

	b, err = os.ReadFile(leafcert.Name())
	require.NoError(t, err)
	assert.Equal(t, b, env.Signatures[0].Certificate)
}

func TestRunHashesOptions(t *testing.T) {
	tests := []struct {
		name         string
		hashesOption []string
		expectErr    bool
	}{
		{
			name:         "Valid RSA key pair",
			hashesOption: []string{"sha256"},
			expectErr:    false,
		},
		{
			name:         "Invalid hashes option",
			hashesOption: []string{"invalidHash"},
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
			require.NoError(t, err)
			signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

			workingDir := t.TempDir()
			attestationPath := filepath.Join(workingDir, "outfile.txt")
			runOptions := options.RunOptions{
				WorkingDir:   workingDir,
				Attestations: []string{},
				Hashes:       tt.hashesOption,
				OutFilePath:  attestationPath,
				StepName:     "teststep",
				Tracing:      false,
			}

			args := []string{
				"bash",
				"-c",
				"echo 'test' > test.txt",
			}

			err = runRun(context.Background(), runOptions, args, signer)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				attestationBytes, err := os.ReadFile(attestationPath)
				require.NoError(t, err)
				env := dsse.Envelope{}
				require.NoError(t, json.Unmarshal(attestationBytes, &env))
			}
		})
	}
}
