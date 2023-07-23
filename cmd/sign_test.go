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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/witness/options"
)

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
