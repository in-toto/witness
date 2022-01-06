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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/testifysec/witness/cmd/options"
	"io"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/rekor"
)

func RunCmd() *cobra.Command {
	o := options.RunOptions{}
	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(o, args)
		},
		Args: cobra.ArbitraryArgs,
	}
	cobra.OnInitialize(initConfig)
	o.AddFlags(cmd)
	cmd.MarkFlagRequired("step")
	return cmd
}

func runRun(ro options.RunOptions, args []string) error {
	signer, err := loadSigner(ro.KeyOptions.SpiffePath, ro.KeyOptions.KeyPath, ro.KeyOptions.CertPath, ro.KeyOptions.IntermediatePaths)
	if err != nil {
		return fmt.Errorf("failed to load signer: %w", err)
	}

	out, err := loadOutfile(ro.OutFilePath)
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}

	defer out.Close()
	attestors, err := attestation.Attestors(ro.Attestations)
	if err != nil {
		return fmt.Errorf("failed to get attestors: %w", err)
	}

	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing)))
	}

	runCtx, err := attestation.NewContext(
		attestors,
		attestation.WithWorkingDir(ro.WorkingDir),
	)

	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	if err := runCtx.RunAttestors(); err != nil {
		return fmt.Errorf("failed to run attestors: %w", err)
	}

	completed := runCtx.CompletedAttestors()
	collection := attestation.NewCollection(ro.StepName, completed)
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

	rekorServer := ro.RekorServer
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
