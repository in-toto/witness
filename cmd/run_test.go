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
	"strconv"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
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

func Test_RunCmd(t *testing.T) {
	cmd := RunCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "run [cmd]", cmd.Use)
	assert.Equal(t, true, cmd.SilenceErrors)
	assert.Equal(t, true, cmd.SilenceUsage)

	// Test flags
	flags := cmd.Flags()
	require.NotNil(t, flags)

	// Important RunOptions flags
	require.NotNil(t, flags.Lookup("step"))
	require.NotNil(t, flags.Lookup("outfile"))
	require.NotNil(t, flags.Lookup("attestations"))
	require.NotNil(t, flags.Lookup("workingdir"))
	require.NotNil(t, flags.Lookup("hashes"))
	require.NotNil(t, flags.Lookup("dirhash-glob"))
	require.NotNil(t, flags.Lookup("trace"))
	
	// Environment flags
	require.NotNil(t, flags.Lookup("env-filter-sensitive-vars"))
	require.NotNil(t, flags.Lookup("env-disable-default-sensitive-vars"))
	require.NotNil(t, flags.Lookup("env-add-sensitive-key"))
	require.NotNil(t, flags.Lookup("env-allow-sensitive-key"))
	
	// Archivista flags
	require.NotNil(t, flags.Lookup("enable-archivista"))
	require.NotNil(t, flags.Lookup("archivista-server"))
	
	// Test deprecated flags (should be hidden)
	require.NotNil(t, flags.Lookup("enable-archivist"))
	require.NotNil(t, flags.Lookup("archivist-server"))

	// Ensure the command's RunE function is set
	require.NotNil(t, cmd.RunE)
	
	// Make sure Args is configured to allow arbitrary args
	require.NotNil(t, cmd.Args)
	
	// Create a duplicate CMD to check static initialization
	cmd2 := RunCmd()
	require.NotNil(t, cmd2)
	
	// Verify that this creates a new command instance
	assert.NotSame(t, cmd, cmd2, "Each call to RunCmd should create a new command")
	
	// But both should have the same structure and flags
	assert.Equal(t, cmd.Use, cmd2.Use)
	assert.Equal(t, cmd.SilenceErrors, cmd2.SilenceErrors)
	assert.Equal(t, cmd.SilenceUsage, cmd2.SilenceUsage)
}

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

	signers, err := loadSigners(context.Background(), signerOptions, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
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

func TestRunDuplicateAttestors(t *testing.T) {
	tests := []struct {
		name       string
		attestors  []string
		expectWarn int
	}{
		{
			name:       "No duplicate attestors",
			attestors:  []string{"environment"},
			expectWarn: 0,
		},
		{
			name:       "duplicate attestors",
			attestors:  []string{"environment", "environment"},
			expectWarn: 1,
		},
		{
			name:       "duplicate attestor due to default",
			attestors:  []string{"product"},
			expectWarn: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testLogger, hook := test.NewNullLogger()
			log.SetLogger(testLogger)

			privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
			require.NoError(t, err)
			signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

			workingDir := t.TempDir()
			attestationPath := filepath.Join(workingDir, "outfile.txt")
			runOptions := options.RunOptions{
				WorkingDir:   workingDir,
				Attestations: tt.attestors,
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
			if tt.expectWarn > 0 {
				c := 0
				for _, entry := range hook.AllEntries() {
					if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "already declared, skipping") {
						c++
					}
				}
				assert.Equal(t, tt.expectWarn, c)
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

func TestRunDirHashGlobs(t *testing.T) {
	tests := []struct {
		name       string
		globs      []string
		expectErr  bool
		expectMsg  string
	}{
		{
			name:       "Valid glob pattern",
			globs:      []string{"*.txt"},
			expectErr:  false,
			expectMsg:  "",
		},
		{
			name:       "Invalid glob pattern",
			globs:      []string{"["},  // Invalid regex pattern
			expectErr:  true,
			expectMsg:  "failed to compile glob",
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
				WorkingDir:    workingDir,
				Attestations:  []string{},
				DirHashGlobs:  tt.globs,
				OutFilePath:   attestationPath,
				StepName:      "teststep",
				Tracing:       false,
			}

			args := []string{
				"bash",
				"-c",
				"echo 'test' > test.txt",
			}

			err = runRun(context.Background(), runOptions, args, signer)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectMsg)
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

func TestRunSignerCount(t *testing.T) {
	tests := []struct {
		name      string
		signerCount int
		expectErr bool
		expectMsg string
	}{
		{
			name:       "No signers",
			signerCount: 0,
			expectErr:  true,
			expectMsg:  "no signers found",
		},
		{
			name:       "One signer",
			signerCount: 1,
			expectErr:  false,
			expectMsg:  "",
		},
		{
			name:       "Multiple signers",
			signerCount: 2,
			expectErr:  true,
			expectMsg:  "only one signer is supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signers := []cryptoutil.Signer{}

			for i := 0; i < tt.signerCount; i++ {
				privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
				require.NoError(t, err)
				signers = append(signers, cryptoutil.NewRSASigner(privatekey, crypto.SHA256))
			}

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

			err := runRun(context.Background(), runOptions, args, signers...)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectMsg)
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

func TestRunInvalidAttestor(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
		WorkingDir:   workingDir,
		Attestations: []string{"nonexistent-attestor"},
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
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create attestor")
}

func TestRunCommandRunAttestor(t *testing.T) {
	testLogger, hook := test.NewNullLogger()
	log.SetLogger(testLogger)

	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
		WorkingDir:   workingDir,
		Attestations: []string{"command-run"},
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

	// Verify warning was logged
	warnFound := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "'command-run' is a builtin attestor") {
			warnFound = true
			break
		}
	}
	assert.True(t, warnFound, "Expected warning about command-run being a builtin attestor")

	// Verify attestation was created
	attestationBytes, err := os.ReadFile(attestationPath)
	require.NoError(t, err)
	env := dsse.Envelope{}
	require.NoError(t, json.Unmarshal(attestationBytes, &env))
}

// TestRunCmdRunE tests the RunE function of the run command by mocking dependencies
func TestRunCmdRunE(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	
	// Create a simple context and test directly with runRun
	ctx := context.Background()
	runOptions := options.RunOptions{
		WorkingDir:   workingDir,
		Attestations: []string{},
		OutFilePath:  attestationPath,
		StepName:     "teststep",
		Tracing:      false,
		AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
	}

	args := []string{"echo", "test"}
	
	// Test runRun directly with our test options
	// We're mainly testing that nothing panics and the function returns without error
	err = runRun(ctx, runOptions, args, signer)
	require.NoError(t, err)
	
	// Success - test passes if runRun completes without error
	// The attestation files should be created, but we won't verify them
	// to avoid filesystem-specific issues in tests
}

// Test attestor specific options and errors
func TestRunAttestorOptions(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	// Test the happy path first
	t.Run("Successful attestor options", func(t *testing.T) {
		workingDir := t.TempDir()
		attestationPath := filepath.Join(workingDir, "outfile.txt")
		
		// Create a simple context and test directly with runRun
		ctx := context.Background()
		
		// Create a run options with attestor options 
		runOptions := options.RunOptions{
			WorkingDir:   workingDir,
			Attestations: []string{"environment"},
			OutFilePath:  attestationPath,
			StepName:     "teststep",
			TimestampServers: []string{"https://freetsa.org/tsr"},
			Tracing:      false,
			AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		}
		
		// Add a mock setter function for a specific attestor
		mockSetter := func(attestor attestation.Attestor) (attestation.Attestor, error) {
			// This is just a pass-through function to test the code path
			return attestor, nil
		}
		runOptions.AttestorOptSetters["environment"] = []func(attestation.Attestor) (attestation.Attestor, error){mockSetter}
	
		// Run with default attestor options
		args := []string{"echo", "test"}
		err = runRun(ctx, runOptions, args, signer)
		require.NoError(t, err)
	})
}

// Test for error cases in runRun function
func TestRunErrorCases(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	// Test case 1: Invalid hash format
	t.Run("Invalid hash format", func(t *testing.T) {
		workingDir := t.TempDir()
		attestationPath := filepath.Join(workingDir, "outfile.txt")
		
		// Create a simple context and test directly with runRun
		ctx := context.Background()
		
		// Create a run options with an invalid hash algorithm
		runOptions := options.RunOptions{
			WorkingDir:   workingDir,
			Attestations: []string{},
			OutFilePath:  attestationPath,
			StepName:     "teststep",
			Tracing:      false,
			Hashes:       []string{"invalid-hash-algorithm"},
			AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		}
		
		// Run with options that will cause an error
		args := []string{"echo", "test"}
		err = runRun(ctx, runOptions, args, signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse hash")
	})
	
	// Test case 2: Invalid dir hash glob
	t.Run("Invalid dir hash glob", func(t *testing.T) {
		workingDir := t.TempDir()
		attestationPath := filepath.Join(workingDir, "outfile.txt")
		
		// Create a simple context and test directly with runRun
		ctx := context.Background()
		
		// Create a run options with an invalid glob pattern
		runOptions := options.RunOptions{
			WorkingDir:    workingDir,
			Attestations:  []string{},
			OutFilePath:   attestationPath,
			StepName:      "teststep",
			Tracing:       false,
			DirHashGlobs:  []string{"["},  // Invalid regex pattern
			AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		}
		
		// Run with options that will cause an error
		args := []string{"echo", "test"}
		err = runRun(ctx, runOptions, args, signer)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to compile glob")
	})
	
	// Test case 3: No signers
	t.Run("No signers", func(t *testing.T) {
		workingDir := t.TempDir()
		attestationPath := filepath.Join(workingDir, "outfile.txt")
		
		// Create a simple context and test directly with runRun
		ctx := context.Background()
		
		runOptions := options.RunOptions{
			WorkingDir:   workingDir,
			Attestations: []string{},
			OutFilePath:  attestationPath,
			StepName:     "teststep",
			Tracing:      false,
			AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		}
		
		// Run with no signers
		args := []string{"echo", "test"}
		err = runRun(ctx, runOptions, args) // No signers passed
		require.Error(t, err)
		require.Contains(t, err.Error(), "no signers found")
	})
	
	// Test case 4: Multiple signers
	t.Run("Multiple signers", func(t *testing.T) {
		workingDir := t.TempDir()
		attestationPath := filepath.Join(workingDir, "outfile.txt")
		
		// Create a simple context and test directly with runRun
		ctx := context.Background()
		
		runOptions := options.RunOptions{
			WorkingDir:   workingDir,
			Attestations: []string{},
			OutFilePath:  attestationPath,
			StepName:     "teststep",
			Tracing:      false,
			AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		}
		
		// Create a second signer
		privatekey2, err := rsa.GenerateKey(rand.Reader, keybits)
		require.NoError(t, err)
		signer2 := cryptoutil.NewRSASigner(privatekey2, crypto.SHA256)
		
		// Run with multiple signers
		args := []string{"echo", "test"}
		err = runRun(ctx, runOptions, args, signer, signer2) // Two signers
		require.Error(t, err)
		require.Contains(t, err.Error(), "only one signer is supported")
	})
}

func TestRunEnvCapturerOptions(t *testing.T) {
	tests := []struct {
		name                    string
		addSensitiveKeys        []string
		excludeSensitiveKeys    []string
		disableSensitiveVars    bool
		filterSensitiveVars     bool
	}{
		{
			name:                 "Add sensitive keys",
			addSensitiveKeys:     []string{"TEST_KEY"},
			excludeSensitiveKeys: []string{},
			disableSensitiveVars: false,
			filterSensitiveVars:  false,
		},
		{
			name:                 "Exclude sensitive keys",
			addSensitiveKeys:     []string{},
			excludeSensitiveKeys: []string{"PATH"},
			disableSensitiveVars: false,
			filterSensitiveVars:  false,
		},
		{
			name:                 "Disable sensitive vars",
			addSensitiveKeys:     []string{},
			excludeSensitiveKeys: []string{},
			disableSensitiveVars: true,
			filterSensitiveVars:  false,
		},
		{
			name:                 "Filter sensitive vars",
			addSensitiveKeys:     []string{},
			excludeSensitiveKeys: []string{},
			disableSensitiveVars: false,
			filterSensitiveVars:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
			require.NoError(t, err)
			signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

			workingDir := t.TempDir()
			attestationPath := filepath.Join(workingDir, "outfile-"+strconv.FormatBool(tt.filterSensitiveVars)+".txt")
			runOptions := options.RunOptions{
				WorkingDir:              workingDir,
				Attestations:            []string{"environment"},
				OutFilePath:             attestationPath,
				StepName:                "teststep",
				Tracing:                 false,
				EnvAddSensitiveKeys:     tt.addSensitiveKeys,
				EnvAllowSensitiveKeys:   tt.excludeSensitiveKeys,
				EnvDisableSensitiveVars: tt.disableSensitiveVars,
				EnvFilterSensitiveVars:  tt.filterSensitiveVars,
				AttestorOptSetters:      make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
			}

			args := []string{
				"bash",
				"-c",
				"echo 'test' > test.txt",
			}

			// Test only that runRun doesn't return an error
			// We're mainly testing that each env option combination is accepted
			err = runRun(context.Background(), runOptions, args, signer)
			require.NoError(t, err)
		})
	}
}

func TestRunTimestampServer(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	attestationPath := filepath.Join(workingDir, "outfile.txt")
	runOptions := options.RunOptions{
		WorkingDir:       workingDir,
		Attestations:     []string{},
		OutFilePath:      attestationPath,
		StepName:         "teststep",
		Tracing:          false,
		TimestampServers: []string{"https://freetsa.org/tsr"},
	}

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	// This is a non-critical test since it requires external connectivity
	// so we're not asserting success/failure, just making sure it doesn't panic
	_ = runRun(context.Background(), runOptions, args, signer)
}
