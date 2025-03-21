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
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SignCmd(t *testing.T) {
	cmd := SignCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "sign [file]", cmd.Use)
	assert.Equal(t, true, cmd.SilenceErrors)
	assert.Equal(t, true, cmd.SilenceUsage)

	// Test flags
	flags := cmd.Flags()
	require.NotNil(t, flags)

	// Test existence of important flags
	assert.NotNil(t, flags.Lookup("infile"))
	assert.NotNil(t, flags.Lookup("outfile"))
	assert.NotNil(t, flags.Lookup("datatype"))
	
	// Test RunE function exists
	assert.NotNil(t, cmd.RunE)
	
	// Create duplicate command to verify static initialization 
	cmd2 := SignCmd()
	require.NotNil(t, cmd2)
	assert.NotSame(t, cmd, cmd2, "Each call to SignCmd should create a new command")
}

func Test_runSignPolicyRSA(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)

	workingDir := t.TempDir()
	testdata := []byte("test")
	require.NoError(t, os.WriteFile(workingDir+"test.txt", testdata, 0644))

	signOptions := options.SignOptions{
		DataType:    "text",
		OutFilePath: workingDir + "outfile.txt",
		InFilePath:  workingDir + "test.txt",
	}

	require.NoError(t, runSign(context.Background(), signOptions, signer))
	signedBytes, err := os.ReadFile(workingDir + "outfile.txt")
	require.NoError(t, err)
	assert.True(t, len(signedBytes) > 0)
}

// Test runSign with error conditions
func Test_runSignErrors(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)
	
	workingDir := t.TempDir()
	testdata := []byte("test")
	testFile := filepath.Join(workingDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, testdata, 0644))
	
	// Test error case: no signers
	t.Run("No signers", func(t *testing.T) {
		signOptions := options.SignOptions{
			DataType:    "text",
			OutFilePath: filepath.Join(workingDir, "outfile.txt"),
			InFilePath:  testFile,
		}
		
		err := runSign(context.Background(), signOptions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no signers found")
	})
	
	// Test error case: multiple signers
	t.Run("Multiple signers", func(t *testing.T) {
		// Create second signer
		privatekey2, err := rsa.GenerateKey(rand.Reader, keybits)
		require.NoError(t, err)
		signer2 := cryptoutil.NewRSASigner(privatekey2, crypto.SHA256)
		
		signOptions := options.SignOptions{
			DataType:    "text",
			OutFilePath: filepath.Join(workingDir, "outfile.txt"),
			InFilePath:  testFile,
		}
		
		err = runSign(context.Background(), signOptions, signer, signer2)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one signer is supported")
	})
	
	// Test error case: file not found
	t.Run("File not found", func(t *testing.T) {
		signOptions := options.SignOptions{
			DataType:    "text",
			OutFilePath: filepath.Join(workingDir, "outfile.txt"),
			InFilePath:  filepath.Join(workingDir, "nonexistent.txt"),
		}
		
		err = runSign(context.Background(), signOptions, signer)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})
}

// Test command connection to runSign by directly calling runSign
func Test_SignCmdRunE(t *testing.T) {
	// Create test data
	tempDir := t.TempDir()
	infilePath := filepath.Join(tempDir, "infile.txt")
	outfilePath := filepath.Join(tempDir, "outfile.txt")
	
	// Create test input file
	err := os.WriteFile(infilePath, []byte("test content"), 0644)
	require.NoError(t, err)
	
	// Create test key
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privatekey, crypto.SHA256)
	
	// Instead of mocking loadSigners, directly call runSign
	signOptions := options.SignOptions{
		DataType:    "text/plain",
		OutFilePath: outfilePath,
		InFilePath:  infilePath,
	}
	
	err = runSign(context.Background(), signOptions, signer)
	require.NoError(t, err)
	
	// Verify file was created
	_, err = os.Stat(outfilePath)
	require.NoError(t, err)
}