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
	"encoding/json"
	"fmt"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
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

	timestampers := []timestamp.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	attestors := []attestation.Attestor{product.New(), material.New()}
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing)))
	}

	for _, a := range ro.Attestations {
		duplicate := false
		for _, att := range attestors {
			if a != att.Name() {
			} else {
				log.Warnf("Attestator %s already declared, skipping", a)
				duplicate = true
				break
			}
		}

		if !duplicate {
			attestor, err := attestation.GetAttestor(a)
			if err != nil {
				return fmt.Errorf("failed to create attestor: %w", err)
			}
			attestors = append(attestors, attestor)
		}
	}

	for _, attestor := range attestors {
		setters, ok := ro.AttestorOptSetters[attestor.Name()]
		if !ok {
			continue
		}

		attestor, err := registry.SetOptions(attestor, setters...)
		if err != nil {
			return fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err)
		}
	}

	var roHashes []cryptoutil.DigestValue
	for _, hashStr := range ro.Hashes {
		hash, err := cryptoutil.HashFromString(hashStr)
		if err != nil {
			return fmt.Errorf("failed to parse hash: %w", err)
		}
		roHashes = append(roHashes, cryptoutil.DigestValue{Hash: hash, GitOID: false})
	}

	results, err := witness.RunWithExports(
		ro.StepName,
		signers[0],
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir), attestation.WithHashes(roHashes)),
		witness.RunWithTimestampers(timestampers...),
	)
	if err != nil {
		return err
	}

	for _, result := range results {
		signedBytes, err := json.Marshal(&result.SignedEnvelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope: %w", err)
		}

		// TODO: Find out explicit way to describe "prefix" in CLI options
		outfile := ro.OutFilePath
		if result.AttestorName != "" {
			outfile += "-" + result.AttestorName + ".json"
		}

		out, err := loadOutfile(outfile)
		if err != nil {
			return fmt.Errorf("failed to open out file: %w", err)
		}
		defer out.Close()

		if _, err := out.Write(signedBytes); err != nil {
			return fmt.Errorf("failed to write envelope to out file: %w", err)
		}

		if ro.ArchivistaOptions.Enable {
			archivistaClient := archivista.New(ro.ArchivistaOptions.Url)
			if gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope); err != nil {
				return fmt.Errorf("failed to store artifact in archivista: %w", err)
			} else {
				log.Infof("Stored in archivista as %v\n", gitoid)
			}
		}
	}
	return nil
}
