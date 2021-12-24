// Copyright 2021 The TestifySec Authors
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
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/rekor"
)

var workingDir string
var attestations []string
var outFilePath string
var stepName string
var rekorServer string
var tracing bool

var runCmd = &cobra.Command{
	Use:           "run [cmd]",
	Short:         "Runs the provided command and records attestations about the execution",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runRun,
	Args:          cobra.ArbitraryArgs,
}

func init() {
	rootCmd.AddCommand(runCmd)
	addKeyFlags(runCmd)
	runCmd.Flags().StringVarP(&workingDir, "workingdir", "d", "", "Directory that commands will be run from")
	runCmd.Flags().StringSliceVarP(&attestations, "attestations", "a", []string{"Environment", "Artifact", "Git"}, "Attestations to record")
	runCmd.Flags().StringVarP(&outFilePath, "outfile", "o", "", "File to write signed data.  Defaults to stdout")
	runCmd.Flags().StringVarP(&stepName, "step", "s", "", "Name of the step being run")
	runCmd.Flags().StringVarP(&rekorServer, "rekor-server", "r", "", "Rekor server to store attestations")
	runCmd.Flags().BoolVar(&tracing, "trace", false, "enable tracing for the command")
	cobra.OnInitialize(initConfig)

}

func runRun(cmd *cobra.Command, args []string) error {
	if stepName == "" {
		return fmt.Errorf("step name is required")
	}

	signer, err := loadSigner()
	if err != nil {
		return fmt.Errorf("failed to load signer: %w", err)
	}

	out, err := loadOutfile()
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}

	defer out.Close()
	attestors, err := attestation.Attestors(attestations)
	if err != nil {
		return fmt.Errorf("failed to get attestors: %w", err)
	}

	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(tracing)))
	}

	runCtx, err := attestation.NewContext(
		attestors,
		attestation.WithWorkingDir(workingDir),
	)

	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	if err := runCtx.RunAttestors(); err != nil {
		return fmt.Errorf("failed to run attestors: %w", err)
	}

	completed := runCtx.CompletedAttestors()
	collection := attestation.NewCollection(stepName, completed)
	data, err := json.Marshal(&collection)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation collection: %w", err)
	}

	statement, err := intoto.NewStatement(attestation.CollectionType, data, collection.Subjects())
	if err != nil {
		return fmt.Errorf("failed to create in-toto statement: %w", err)
	}

	statementJson, err := json.Marshal(&statement)
	if err != nil {
		return fmt.Errorf("failed to marshal in-toto statement: %w", err)
	}

	dataReader := bytes.NewReader(statementJson)
	signedBytes := bytes.Buffer{}
	writer := io.MultiWriter(out, &signedBytes)
	if err := witness.Sign(dataReader, intoto.PayloadType, writer, signer); err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

	if rekorServer != "" {
		verifier, err := signer.Verifier()
		if err != nil {
			return fmt.Errorf("failed to get verifier from signer: %w", err)
		}

		pubKeyBytes, err := verifier.Bytes()
		if err != nil {
			return fmt.Errorf("failed to get bytes from verifier: %w", err)
		}

		resp, err := rekor.StoreArtifact(rekorServer, signedBytes.Bytes(), pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to store artifact in rekor: %w", err)
		}

		fmt.Printf("Rekor entry added at %v%v\n", rekorServer, resp.Location)
	}

	return nil
}
