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

	// Add the `RunWithUserDefinedSubject` option if user-defined subjects are provided
	runOptions := []witness.RunOption{
		witness.RunWithSigners(signers...),
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir),
			attestation.WithHashes(roHashes)),
		witness.RunWithTimestampers(timestampers...),
	}

	// Aggregate all user-defined subjects into a single map
	allSubjects := make(map[string]cryptoutil.DigestSet)

	// Iterate over user-defined subjects and add them to the aggregated map
	for _, userDefinedSubject := range ro.UserDefinedSubjects {
		fmt.Printf("User-defined subject: %v\n", userDefinedSubject)
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(userDefinedSubject), roHashes)
		if err != nil {
			log.Debugf("(witness) failed to record user-defined subject %v: %v", userDefinedSubject, err)
			continue
		}
		// Add the user-defined subject to the aggregated map
		allSubjects["https://witness.dev/internal/user:"+userDefinedSubject] = ds
	}

	// Add the aggregated subjects to the run options
	if len(allSubjects) > 0 {
		runOptions = append(runOptions, witness.RunWithUserDefinedSubject(allSubjects))
	}

	results, err := witness.RunWithExports(ro.StepName, runOptions...)
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
