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
	"encoding/json"
	"os"
	"testing"

	"github.com/testifysec/witness/cmd/witness/options"
	"github.com/testifysec/witness/pkg/dsse"
)

func Test_runSignPolicyRSA(t *testing.T) {
	priv, _ := rsakeypair(t)

	keyOptions := options.KeyOptions{
		KeyPath: priv.Name(),
	}

	workingDir := t.TempDir()

	testdata := []byte("test")

	err := os.WriteFile(workingDir+"test.txt", testdata, 0644)
	if err != nil {
		t.Error(err)
	}

	signOptions := options.SignOptions{
		KeyOptions:  keyOptions,
		DataType:    "text",
		OutFilePath: workingDir + "outfile.txt",
		InFilePath:  workingDir + "test.txt",
	}

	err = runSign(signOptions)
	if err != nil {
		t.Error(err)
	}

	signedBytes, err := os.ReadFile(workingDir + "outfile.txt")
	if err != nil {
		t.Error(err)
	}

	if len(signedBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

}

func Test_runSignPolicyCA(t *testing.T) {
	_, intermediates, leafcert, leafkey := fullChain(t)

	keyOptions := options.KeyOptions{
		KeyPath: leafkey.Name(),
		IntermediatePaths: []string{
			intermediates[0].Name(),
		},
		CertPath: leafcert.Name(),
	}

	workingDir := t.TempDir()

	testdata := []byte("test")

	err := os.WriteFile(workingDir+"test.txt", testdata, 0644)
	if err != nil {
		t.Error(err)
	}

	signOptions := options.SignOptions{
		KeyOptions:  keyOptions,
		DataType:    "text",
		OutFilePath: workingDir + "outfile.txt",
		InFilePath:  workingDir + "test.txt",
	}

	err = runSign(signOptions)
	if err != nil {
		t.Error(err)
	}

	signedBytes, err := os.ReadFile(workingDir + "outfile.txt")
	if err != nil {
		t.Error(err)
	}

	if len(signedBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

	t.Logf("%s", signedBytes)

	envelope := dsse.Envelope{}

	err = json.Unmarshal(signedBytes, &envelope)
	if err != nil {
		t.Error(err)
	}

	if len(envelope.Signatures) != 1 {
		t.Errorf("Unexpected number of signatures")
	}

	if len(envelope.Signatures[0].Intermediates) != 1 {
		t.Errorf("Unexpected number of signature bytes")
	}
}
