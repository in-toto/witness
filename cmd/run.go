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

	"github.com/spf13/cobra"
	witness "github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivist"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/witness/options"
)

func RunCmd() *cobra.Command {
	o := options.RunOptions{}
	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd.Context(), o, args)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

func runRun(ctx context.Context, ro options.RunOptions, args []string) error {
	signers, errors := loadSigners(ctx, ro.KeyOptions)
	if len(errors) > 0 {
		for _, err := range errors {
			log.Error(err)
		}
		return fmt.Errorf("failed to load signers")
	}

	if len(signers) > 1 {
		log.Error("only one signer is supported")
		return fmt.Errorf("only one signer is supported")
	}

	if len(signers) == 0 {
		log.Error("no signers found")
		return fmt.Errorf("no signers found")
	}

	signer := signers[0]

	out, err := loadOutfile(ro.OutFilePath)
	if err != nil {
		return fmt.Errorf("failed to open out file: %w", err)
	}

	defer out.Close()

	result, err := witness.Run(
		ro.StepName,
		signer,
		witness.RunWithTracing(ro.Tracing),
		witness.RunWithCommand(args),
		witness.RunWithAttestors(ro.Attestations),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir)),
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

	if ro.ArchivistOptions.Enable {
		archivistClient := archivist.New(ro.ArchivistOptions.Url)
		if gitoid, err := archivistClient.Store(ctx, result.SignedEnvelope); err != nil {
			return fmt.Errorf("failed to store artifact in archivist: %w", err)
		} else {
			log.Infof("Stored in archivist as %v\n", gitoid)
		}
	}

	return nil
}
