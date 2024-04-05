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
	"fmt"
	logg "log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/file"
	"github.com/in-toto/witness/options"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunRSAKeyPair(t *testing.T) {
	tests := []runTest{
		{
			name: "Normal RSA Keypair Signing",
			options: options.RunOptions{
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			args:       []string{},
			signers:    []cryptoutil.Signer{},
			expectLogs: nil,
			requireErr: "",
		},
	}

	testRun(t, tests)
}

func Test_runRunRSACA(t *testing.T) {
	_, intermediates, leafCert, leafKey := fullChain(t)
	signerOptions := options.SignerOptions{}
	signerOptions["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
		func(sp signer.SignerProvider) (signer.SignerProvider, error) {
			fsp := sp.(file.FileSignerProvider)
			fsp.KeyPath = leafKey.Name()
			fsp.IntermediatePaths = []string{intermediates[0].Name()}
			for _, intermediate := range intermediates {
				fsp.IntermediatePaths = append(fsp.IntermediatePaths, intermediate.Name())
			}

			fsp.CertPath = leafCert.Name()
			return fsp, nil
		},
	}

	signers, err := loadSigners(context.Background(), signerOptions, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
	require.NoError(t, err)

	tests := []runTest{
		{
			name: "Valid hashes option",
			options: options.RunOptions{
				SignerOptions: signerOptions,
				Attestations:  []string{},
				StepName:      "teststep",
				Tracing:       false,
			},
			args:         []string{},
			signers:      signers,
			expectLogs:   nil,
			requireErr:   "",
			intermediate: intermediates[0],
			leafCert:     leafCert,
		},
	}

	testRun(t, tests)
}

func TestRunHashesOptions(t *testing.T) {
	workingDir := t.TempDir()
	tests := []runTest{
		{
			name: "Valid hashes option",
			options: options.RunOptions{
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Hashes:       []string{"sha256"},
				Tracing:      false,
			},
			args:       []string{},
			signers:    []cryptoutil.Signer{},
			expectLogs: nil,
			requireErr: "",
		},
		{
			name: "Invalid hashes option",
			options: options.RunOptions{
				Attestations: []string{"environment"},
				StepName:     "teststep",
				WorkingDir:   workingDir,
				OutFile:      filepath.Join(workingDir, "outfile.txt"),
				Hashes:       []string{"invalidHash"},
				Tracing:      false,
			},
			args:       []string{},
			signers:    []cryptoutil.Signer{},
			requireErr: "failed to parse hash: unsupported hash function: invalidHash",
		},
	}

	testRun(t, tests)
}

func TestRunOutputFileHandling(t *testing.T) {
	tempDir := t.TempDir()
	tests := []runTest{
		{
			name: "OutFile specified",
			options: options.RunOptions{
				WorkingDir:   tempDir,
				OutFile:      filepath.Join(tempDir, "outfile.txt"),
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			expectLogs: []tlog{
				{
					level:   logrus.WarnLevel,
					message: "--outfile is deprecated, please use --output instead",
				},
			},
			requireErr: "",
		},
		{
			name: "OutFilePath specified with default prefixes",
			options: options.RunOptions{
				OutFilePath:  tempDir,
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			expectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: fmt.Sprintf("attestation written to %s/teststep.collection.json", tempDir),
				},
			},
			unexpectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: "--outfile is deprecated, please use --output instead",
				},
			},
			requireErr: "",
		},
		{
			name: "OutFilePath specified with set prefix",
			options: options.RunOptions{
				OutFilePath:   tempDir,
				OutFilePrefix: "super-secret-prefix",
				Attestations:  []string{"environment"},
				StepName:      "teststep",
				Tracing:       false,
			},
			expectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: fmt.Sprintf("attestation written to %s/super-secret-prefix.collection.json", tempDir),
				},
			},
			unexpectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: "--outfile is deprecated, please use --output instead",
				},
			},
			requireErr: "",
		},
		{
			name: "OutFilePath specified with set prefix and exported attestations",
			options: options.RunOptions{
				OutFilePath:   tempDir,
				OutFilePrefix: "super-secret-prefix",
				Attestations:  []string{"environment", "slsa", "link"},
				StepName:      "teststep",
				Tracing:       false,
			},
			exportedAtts: []string{"slsa", "link"},
			expectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: fmt.Sprintf("attestation written to %s/super-secret-prefix.collection.json", tempDir),
				},
			},
			unexpectLogs: []tlog{
				{
					level:   logrus.InfoLevel,
					message: "--outfile is deprecated, please use --output instead",
				},
			},
			requireErr: "",
		},
		{
			name: "OutFilePath specified with invalid prefix",
			options: options.RunOptions{
				OutFilePath:   tempDir,
				OutFilePrefix: "(&*^*&TYUTY)///$$$#",
				Attestations:  []string{"environment"},
				StepName:      "teststep",
				Tracing:       false,
			},
			requireErr: fmt.Sprintf("failed to open out file: failed to create output file: open %s/(&*^*&TYUTY)/$$$#.collection.json: no such file or directory", tempDir),
		},
		{
			name: "Both old and new options specified",
			options: options.RunOptions{
				WorkingDir:   tempDir,
				OutFile:      filepath.Join(tempDir, "outfile.txt"),
				OutFilePath:  tempDir,
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			expectLogs: nil,
			requireErr: "cannot use both --outfile and --output",
		},
	}

	testRun(t, tests)
}

func TestRunDuplicateAttestors(t *testing.T) {
	tests := []runTest{
		{
			name: "No duplicate attestors",
			options: options.RunOptions{
				Attestations: []string{"environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			args:       []string{},
			signers:    []cryptoutil.Signer{},
			expectLogs: nil,
			requireErr: "",
		},
		{
			name: "Duplicate attestors",
			options: options.RunOptions{
				Attestations: []string{"environment", "environment"},
				StepName:     "teststep",
				Tracing:      false,
			},
			args:    []string{},
			signers: []cryptoutil.Signer{},
			expectLogs: []tlog{
				{
					level:   logrus.WarnLevel,
					message: "Attestor environment already declared, skipping",
				},
			},
			requireErr: "",
		},
		{
			name: "Duplicate attestor due to default",
			options: options.RunOptions{
				Attestations: []string{"product"},
				StepName:     "teststep",
				Tracing:      false,
			},
			args:    []string{},
			signers: []cryptoutil.Signer{},
			expectLogs: []tlog{
				{
					level:   logrus.WarnLevel,
					message: "Attestor product already declared, skipping",
				},
			},
			requireErr: "",
		},
	}

	testRun(t, tests)
}

type runTest struct {
	name         string
	options      options.RunOptions
	args         []string
	signers      []cryptoutil.Signer
	intermediate *os.File
	leafCert     *os.File
	expectLogs   []tlog
	unexpectLogs []tlog
	requireErr   string
	exportedAtts []string
}

type tlog struct {
	level   logrus.Level
	message string
}

func testRun(t *testing.T, tests []runTest) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(tt.name)
			testLogger, hook := test.NewNullLogger()
			log.SetLogger(testLogger)

			ss := tt.signers
			if len(ss) == 0 {
				privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
				require.NoError(t, err)
				ss = []cryptoutil.Signer{cryptoutil.NewRSASigner(privatekey, crypto.SHA256)}
			}

			args := tt.args
			if len(args) == 0 {
				args = []string{
					"bash",
					"-c",
					"echo 'test' > test.txt",
				}
			}

			var attestationPaths []string
			if tt.options.OutFile != "" && tt.options.WorkingDir == "" {
				logg.Fatal("test error: WorkingDir must be set if OutFile is set for tests")
			} else if tt.options.OutFile != "" {
				if !strings.Contains(tt.options.OutFile, tt.options.WorkingDir) {
					logg.Fatal("test error: OutFile must be a full path inside the working directory")
				}
				attestationPaths = []string{tt.options.OutFile}
			} else {
				if tt.options.WorkingDir == "" {
					tt.options.WorkingDir = t.TempDir()
				}

				if tt.options.OutFilePath == "" {
					tt.options.OutFilePath = tt.options.WorkingDir
				}

				var prefix string
				if tt.options.OutFilePrefix != "" {
					prefix = tt.options.OutFilePrefix
				} else {
					prefix = tt.options.StepName
				}
				attestationPaths = []string{filepath.Join(tt.options.OutFilePath, fmt.Sprintf("%s.collection.json", prefix))}
				for _, att := range tt.exportedAtts {
					attestationPaths = append(attestationPaths, filepath.Join(tt.options.OutFilePath, fmt.Sprintf("%s.%s.json", prefix, att)))
				}
			}

			err := runRun(context.Background(), tt.options, args, ss...)
			var logs []tlog
			if len(tt.expectLogs) > 0 {
				for _, entry := range hook.AllEntries() {
					logs = append(logs, tlog{level: entry.Level, message: entry.Message})
				}

				for _, l := range tt.expectLogs {
					assert.Contains(t, logs, l)
				}
			}
			if len(tt.unexpectLogs) > 0 {
				for _, l := range tt.unexpectLogs {
					assert.NotContains(t, logs, l)
				}
			}

			if tt.requireErr != "" {
				assert.Equal(t, tt.requireErr, err.Error())
			} else {
				require.NoError(t, err)
				// NOTE: For tests, make sure to set the OutFile to the entire path of the file
				for _, attestationPath := range attestationPaths {
					attestationBytes, err := os.ReadFile(attestationPath)
					require.NoError(t, err)
					env := dsse.Envelope{}
					require.NoError(t, json.Unmarshal(attestationBytes, &env))
					if tt.intermediate != nil && tt.leafCert != nil {
						b, err := os.ReadFile(tt.intermediate.Name())
						require.NoError(t, err)
						assert.Equal(t, b, env.Signatures[0].Intermediates[0])

						b, err = os.ReadFile(tt.leafCert.Name())
						require.NoError(t, err)
						assert.Equal(t, b, env.Signatures[0].Certificate)
					}
				}
			}
		})
	}
}
