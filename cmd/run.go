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
	"io"

	"github.com/testifysec/witness/cmd/options"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/attestation/material"
	"github.com/testifysec/witness/pkg/attestation/product"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/log"
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

	o.AddFlags(cmd)
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

	//set up attestors
	attestors, err := attestation.Attestors(ro.Attestations)
	if err != nil {
		return fmt.Errorf("failed to get attestors: %w", err)
	}

	//these are internal attestors and should always run in the order material -> commandrun -> product
	//the attestor order is important because the product attestor will use the material attestor's data
	//post attestors expect data produced by the product attestor
	productAttestor := product.New()
	materialAttestor := material.New()
	commandRunAttestor := commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing))

	attestors = append(attestors, productAttestor, materialAttestor, commandRunAttestor)

	//load attestors into context
	runCtx, err := attestation.NewContext(
		ro.StepName,
		attestors,
		attestation.WithWorkingDir(ro.WorkingDir),
	)

	if err != nil {
		return fmt.Errorf("failed to create attestation context: %w", err)
	}

	//run attestor lifecycle
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

		rc, err := rekor.New(rekorServer)
		if err != nil {
			return fmt.Errorf("failed to get initialize Rekor client: %w", err)
		}

		resp, err := rc.StoreArtifact(signedBytes.Bytes(), pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to store artifact in rekor: %w", err)
		}

		log.Infof("Rekor entry added at %v%v\n", rekorServer, resp.Location)
	}

	return nil
}
