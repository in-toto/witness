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

	"github.com/gobwas/glob"
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
	"github.com/in-toto/witness/internal/errors"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

var alwaysRunAttestors = []attestation.Attestor{product.New(), material.New()}

func RunCmd() *cobra.Command {
	o := options.RunOptions{
		AttestorOptSetters:       make(map[string][]func(attestation.Attestor) (attestation.Attestor, error)),
		SignerOptions:            options.SignerOptions{},
		KMSSignerProviderOptions: options.KMSSignerProviderOptions{},
	}

	cmd := &cobra.Command{
		Use:           "run [cmd]",
		Short:         "Runs the provided command and records attestations about the execution",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			signers, err := loadSigners(cmd.Context(), o.SignerOptions, o.KMSSignerProviderOptions, providersFromFlags("signer", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signers: %w", err)
			}

			return runRun(cmd.Context(), o, args, signers...)
		},
		Args: cobra.ArbitraryArgs,
	}

	o.AddFlags(cmd)
	return cmd
}

// isAttestorError determines if an error is attestor-related
func isAttestorError(err error) bool {
	return errors.IsAttestorError(err)
}

// handleInfraError handles infrastructure operation errors based on continue flags
// Returns true if execution should continue, and the error if it should be tracked
func handleInfraError(ro options.RunOptions, err error, operationDesc string, commandSucceeded bool) (bool, error) {
	if !commandSucceeded {
		return false, nil
	}
	
	// Wrap the error with infrastructure error type
	infraErr := errors.NewInfrastructureError(operationDesc, err)
	
	if ro.ContinueOnAllErrors {
		log.Warnf("Failed to %s: %v", operationDesc, err)
		log.Warnf("Continuing due to --continue-on-errors flag")
		return true, infraErr
	} else if ro.ContinueOnInfraError {
		log.Warnf("Failed to %s: %v", operationDesc, err)
		log.Warnf("Continuing due to --continue-on-infra-error flag")
		return true, infraErr
	}
	
	return false, nil
}

// handleErrorWithContinueFlags applies the appropriate error handling logic based on flags
// Returns true if execution should continue, false if the error should be returned
func handleErrorWithContinueFlags(ro options.RunOptions, err error, commandSucceeded bool) (bool, error, error) {
	var infraError, attestorError error
	
	// If command didn't succeed or no continue flags are set, don't continue
	if !commandSucceeded {
		return false, nil, nil
	}
	
	// Check if the all-errors flag is set, which takes precedence
	if ro.ContinueOnAllErrors {
		log.Warnf("Encountered error: %v", err)
		log.Warnf("Continuing due to --continue-on-errors flag")
		
		// Still classify the error for summary purposes
		if isAttestorError(err) {
			attestorError = err
		} else {
			// Default to infrastructure error if not an attestor error
			infraError = errors.NewInfrastructureError("run command", err)
		}
		return true, infraError, attestorError
	}
	
	// Check specific error type flags
	isAttestor := isAttestorError(err)
	if isAttestor && ro.ContinueOnAttestorError {
		log.Warnf("Encountered attestor error: %v", err)
		log.Warnf("Continuing due to --continue-on-attestor-error flag")
		attestorError = err
		return true, infraError, attestorError
	} else if !isAttestor && ro.ContinueOnInfraError {
		log.Warnf("Encountered infrastructure error: %v", err)
		log.Warnf("Continuing due to --continue-on-infra-error flag")
		infraError = errors.NewInfrastructureError("run command", err)
		return true, infraError, attestorError
	}
	
	// No applicable flag was set, don't continue
	return false, nil, nil
}

func runRun(ctx context.Context, ro options.RunOptions, args []string, signers ...cryptoutil.Signer) error {
	if len(signers) > 1 {
		return errors.NewInfrastructureError("signer validation", fmt.Errorf("only one signer is supported"))
	}

	if len(signers) == 0 {
		return errors.NewInfrastructureError("signer validation", fmt.Errorf("no signers found"))
	}

	// Track if wrapped command succeeded but we had errors
	var commandSucceeded bool
	var infraError error
	var attestorError error

	timestampers := []timestamp.Timestamper{}
	for _, url := range ro.TimestampServers {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	attestors := alwaysRunAttestors
	if len(args) > 0 {
		attestors = append(attestors, commandrun.New(commandrun.WithCommand(args), commandrun.WithTracing(ro.Tracing)))
	}

	for _, a := range ro.Attestations {
		if a == "command-run" {
			log.Warnf("'command-run' is a builtin attestor and cannot be called with --attestations flag")
			continue
		}

		duplicate := false
		for _, att := range attestors {
			if a != att.Name() {
			} else {
				log.Warnf("Attestor %s already declared, skipping", a)
				duplicate = true
				break
			}
		}

		if !duplicate {
			attestor, err := attestation.GetAttestor(a)
			if err != nil {
				return errors.NewAttestorError(a, fmt.Errorf("failed to create attestor: %w", err))
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
			return errors.NewAttestorError(attestor.Name(), fmt.Errorf("failed to set attestor option for %v: %w", attestor.Type(), err))
		}
	}

	var roHashes []cryptoutil.DigestValue
	for _, hashStr := range ro.Hashes {
		hash, err := cryptoutil.HashFromString(hashStr)
		if err != nil {
			return errors.NewInfrastructureError("parse hash", fmt.Errorf("failed to parse hash: %w", err))
		}
		roHashes = append(roHashes, cryptoutil.DigestValue{Hash: hash, GitOID: false})
	}

	for _, dirHashGlobItem := range ro.DirHashGlobs {
		_, err := glob.Compile(dirHashGlobItem)
		if err != nil {
			return errors.NewInfrastructureError("compile glob", fmt.Errorf("failed to compile glob: %v", err))	
		}
	}

	results, err := witness.RunWithExports(
		ro.StepName,
		witness.RunWithSigners(signers...),
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(
			attestation.WithWorkingDir(ro.WorkingDir),
			attestation.WithHashes(roHashes),
			attestation.WithDirHashGlob(ro.DirHashGlobs),
			attestation.WithEnvCapturer(
				ro.EnvAddSensitiveKeys, ro.EnvExcludeSensitiveKeys, ro.EnvDisableSensitiveVars, ro.EnvFilterSensitiveVars,
			),
		),
		witness.RunWithTimestampers(timestampers...),
	)
	
	// Check if command ran successfully
	if len(args) > 0 { // Only check for command success if a command was run
		for _, result := range results {
			if result.AttestorName == "command-run" {
				// Command completed and we have the attestation, so it succeeded
				commandSucceeded = true
				break
			}
		}
	} else {
		// If no command was specified, we're just collecting attestations
		// In this case, treat as if command succeeded for flag purposes
		commandSucceeded = true
	}
	
	if err != nil {
		// Apply error handling logic based on flags
		shouldContinue, newInfraErr, newAttestorErr := handleErrorWithContinueFlags(ro, err, commandSucceeded)
		if shouldContinue {
			// Update the error tracking variables
			if newInfraErr != nil {
				infraError = newInfraErr
			}
			if newAttestorErr != nil {
				attestorError = newAttestorErr
			}
		} else {
			// If we shouldn't continue, return the error
			return err
		}
	}

	for _, result := range results {
		signedBytes, err := json.Marshal(&result.SignedEnvelope)
		if err != nil {
			shouldContinue, newInfraErr := handleInfraError(ro, err, "marshal envelope", commandSucceeded)
			if shouldContinue {
				infraError = newInfraErr
				continue // Skip to next result
			} else {
				return fmt.Errorf("failed to marshal envelope: %w", err)
			}
		}

		// TODO: Find out explicit way to describe "prefix" in CLI options
		outfile := ro.OutFilePath
		if result.AttestorName != "" {
			outfile += "-" + result.AttestorName + ".json"
		}

		out, err := loadOutfile(outfile)
		if err != nil {
			shouldContinue, newInfraErr := handleInfraError(ro, err, fmt.Sprintf("open out file %s", outfile), commandSucceeded)
			if shouldContinue {
				infraError = newInfraErr
				continue // Skip to next result
			} else {
				return fmt.Errorf("failed to open out file: %w", err)
			}
		}
		defer out.Close()

		if _, err := out.Write(signedBytes); err != nil {
			shouldContinue, newInfraErr := handleInfraError(ro, err, fmt.Sprintf("write envelope to file %s", outfile), commandSucceeded)
			if shouldContinue {
				infraError = newInfraErr
				continue // Skip to next result
			} else {
				return fmt.Errorf("failed to write envelope to out file: %w", err)
			}
		}

		if ro.ArchivistaOptions.Enable {
			archivistaClient := archivista.New(ro.ArchivistaOptions.Url)
			gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope)
			if err != nil {
				shouldContinue, newInfraErr := handleInfraError(ro, err, "store artifact in archivista", commandSucceeded)
				if shouldContinue {
					infraError = newInfraErr
				} else {
					return fmt.Errorf("failed to store artifact in archivista: %w", err)
				}
			} else {
				log.Infof("Stored in archivista as %v\n", gitoid)
			}
		}
	}
	
	// Display summary warnings if we had errors but continued
	if commandSucceeded && (attestorError != nil || infraError != nil) {
		// Show a combined message if we used the combined flag
		if ro.ContinueOnAllErrors {
			log.Warnf("Command completed successfully, but encountered errors")
			if attestorError != nil {
				log.Warnf("Some attestations may be missing")
			}
			if infraError != nil {
				log.Warnf("Some attestation functionality may have been compromised")
			}
		} else {
			// Show specific messages for specific flags
			if attestorError != nil && ro.ContinueOnAttestorError {
				log.Warnf("Command completed successfully, but encountered attestor errors")
				log.Warnf("Some attestations may be missing")
			}
			
			if infraError != nil && ro.ContinueOnInfraError {
				log.Warnf("Command completed successfully, but encountered infrastructure errors")
				log.Warnf("Some attestation functionality may have been compromised")
			}
		}
		
		// We had errors but continued, so return success
		return nil
	}
	return nil
}
