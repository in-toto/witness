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
	"os"
	"testing"

	"github.com/testifysec/witness/cmd/witness/options"
)

func Test_runSignPolicyRSA(t *testing.T) {
	priv, _ := rsakeypair(t)

	keyOptions := options.KeyOptions{
		KeyPath: priv.Name(),
	}

	err := os.MkdirAll("/tmp/witness", 0755)
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll("/tmp/witness")

	testdata := []byte("test")

	err = os.WriteFile("/tmp/witness/test.txt", testdata, 0644)
	if err != nil {
		t.Error(err)
	}

	signOptions := options.SignOptions{
		KeyOptions:  keyOptions,
		DataType:    "text",
		OutFilePath: "/tmp/witness/outfile.txt",
		InFilePath:  "/tmp/witness/test.txt",
	}

	err = runSign(signOptions)
	if err != nil {
		t.Error(err)
	}

	signedBytes, err := os.ReadFile("/tmp/witness/outfile.txt")
	if err != nil {
		t.Error(err)
	}

	if len(signedBytes) < 1 {
		t.Errorf("Unexpected output size")
	}

}
