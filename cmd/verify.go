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
	"fmt"
	"github.com/testifysec/witness/cmd/options"
	"io"
	"os"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/policy"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(vo, args)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(vo options.VerifyOptions, args []string) error {
	keyFile, err := os.Open(vo.KeyPath)
	if err != nil {
		return fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	verifier, err := cryptoutil.NewVerifierFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	inFile, err := os.Open(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("could not open file to sign: %v", err)
	}

	defer inFile.Close()
	policyEnvelope, err := witness.VerifySignature(inFile, verifier)
	if err != nil {
		return fmt.Errorf("could not verify policy: %v", err)
	}

	policy := policy.Policy{}
	err = json.Unmarshal(policyEnvelope.Payload, &policy)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %v", err)
	}

	attestationFiles := []io.Reader{}
	for _, path := range vo.AttestationFilePaths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}

		defer file.Close()
		attestationFiles = append(attestationFiles, file)
	}

	return policy.Verify(attestationFiles)
}
