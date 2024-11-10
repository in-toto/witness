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
	"fmt"
	"os"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

func SignCmd() *cobra.Command {
	so := options.SignOptions{
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:               "sign [file]",
		Short:             "Signs a file",
		Long:              "Signs a file with the provided key source and outputs the signed file to the specified destination",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			signers, err := loadSigners(cmd.Context(), so.SignerOptions, so.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}

			return runSign(cmd.Context(), so, signers...)
		},
	}

	so.AddFlags(cmd)
	return cmd
}

// todo: this logic should be broken out and moved to pkg/
// we need to abstract where keys are coming from, etc
func runSign(ctx context.Context, so options.SignOptions, signers ...cryptoutil.Signer) error {
	if len(signers) > 1 {
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	timestampers := []timestamp.Timestamper{}
	for _, url := range so.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	inFile, err := os.Open(so.InFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %w", err)
	}

	outFile, err := loadOutfile(so.OutFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()

	// Aggregate all user-defined subjects into a single map
	allSubjects := make(map[string]cryptoutil.DigestSet)

	// Iterate over user-defined subjects and add them to the aggregated map
	for _, userDefinedSubject := range so.UserDefinedSubjects {
		fmt.Printf("User-defined subject: %v\n", userDefinedSubject)
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(userDefinedSubject),
			[]cryptoutil.DigestValue{{
				Hash:   crypto.SHA256,
				GitOID: false,
			}})

		if err != nil {
			log.Debugf("(witness) failed to record user-defined subject %v: %v", userDefinedSubject, err)
			continue
		}
		// Add the user-defined subject to the aggregated map
		allSubjects["https://witness.dev/internal/user:"+userDefinedSubject] = ds
	}

	return witness.Sign(inFile, so.DataType, outFile, dsse.SignWithSigners(signers[0]),
		dsse.SignWithTimestampers(timestampers...), dsse.SignWithUserDefinedSubject(allSubjects))
}
