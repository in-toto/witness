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
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivista"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/commandrun"
	"github.com/testifysec/go-witness/attestation/material"
	"github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/registry"
	"github.com/testifysec/go-witness/timestamp"
	"github.com/testifysec/witness/options"
)

func RunCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters: make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:      options.SignerOptions{},
	}

	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			signers, err := loadSigners(cmd.Context(), o.SignerOptions, signerProvidersFromFlags(cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signers")
			}

			return runRun(cmd.Context(), o, args, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, signers ...cryptoutil.Signer) error {
	if len(signers) > 1 {
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	out, err := loadOutfile(ro.OutFilePath)
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}

	timestampers := []dsse.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	attestors := []attestation.Attestor{product.New(), material.New()}
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing)))
	}

	addtlAttestors, err := attestation.Attestors(ro.Attestations)
	if err != nil {
		return fmt.Errorf("failed to create attestors := %w", err)
	}

	attestors = append(attestors, addtlAttestors...)
	for _, attestor := range attestors {
		setters, ok := ro.AttestorOptSetters[attestor.Name()]
		if !ok {
			continue
		}

		attestor, err = registry.SetOptions(attestor, setters...)
		if err != nil {
			return fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err)
		}
	}

	var roHashes []crypto.Hash
	for _, hashStr := range ro.Hashes {
		hash, err := cryptoutil.HashFromString(hashStr)
		if err != nil {
			return fmt.Errorf("failed to parse hash: %w", err)
		}
		roHashes = append(roHashes, hash)
	}

	defer out.Close()
	result, err := witness.Run(
		ro.StepName,
		signers[0],
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir), attestation.WithHashes(roHashes)),
		witness.RunWithTimestampers(timestampers...),
	)

	if err != nil {
		return err
	}

	signedBytes, err := json.Marshal(&result.SignedEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	if _, err := out.Write(signedBytes); err != nil {
		return fmt.Errorf("failed to write envelope to out file: %w", err)
	}

	if ro.ArchivistaOptions.Enable {
		archivistaClient := archivista.New(ro.ArchivistaOptions.Url)
		if gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope); err != nil {
			return fmt.Errorf("failed to store artifact in archivist: %w", err)
		} else {
			log.Infof("Stored in archivist as %v\n", gitoid)
		}
	}

	return nil
}
