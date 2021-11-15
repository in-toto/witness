package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	rekorclient "github.com/sigstore/rekor/pkg/client"
	rekoreentries "github.com/sigstore/rekor/pkg/generated/client/entries"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/spf13/cobra"
	witness "gitlab.com/testifysec/witness-cli/pkg"
	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/intoto"
	"gitlab.com/testifysec/witness-cli/pkg/run"
)

var workingDir string
var attestations []string
var outFilePath string
var stepName string
var rekorServer string

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
	runCmd.Flags().StringVarP(&workingDir, "workingdir", "d", "", "Directory that commands will be run from")
	runCmd.Flags().StringArrayVarP(&attestations, "attestations", "a", []string{"CommandRun"}, "Attestations to record")
	runCmd.Flags().StringVarP(&outFilePath, "outfile", "o", "", "File to write signed data.  If no file is provided data will be printed to stdout")
	runCmd.Flags().StringVarP(&stepName, "step", "s", "", "Name of the step being run")
	runCmd.Flags().StringVarP(&rekorServer, "rekor-server", "r", "", "If provided the created attestation will be pushed to the provided rekor server")
	runCmd.MarkFlagRequired("step")
}

func runRun(cmd *cobra.Command, args []string) error {
	signer, err := loadSigner()
	if err != nil {
		return err
	}

	out, err := loadOutfile()
	if err != nil {
		return err
	}

	defer out.Close()
	attestorFactories, err := attestation.GetFactories(attestations)
	if err != nil {
		return err
	}

	runCtx, err := run.New(
		run.WithCommands([][]string{args}),
		run.WithWorkingDir(workingDir),
	)

	if err != nil {
		return err
	}

	runResult, err := runCtx.Run()
	if err != nil {
		return err
	}

	attestors := make([]attestation.Attestor, 0)
	for _, factory := range attestorFactories {
		attestor := factory()
		err := attestor.Attest(runResult)
		if err != nil {
			return err
		}

		attestors = append(attestors, attestor)
	}

	collection := attestation.NewCollection(stepName, attestors)
	data, err := json.Marshal(&collection)
	if err != nil {
		return err
	}

	statment := intoto.NewStatement(attestation.CollectionDataType, data, collection.Subjects())
	statmentJson, err := json.Marshal(&statment)
	if err != nil {
		return err
	}

	dataReader := bytes.NewReader(statmentJson)
	signedBytes := bytes.Buffer{}
	writer := io.MultiWriter(out, &signedBytes)
	if err := witness.Sign(dataReader, intoto.PayloadType, writer, signer); err != nil {
		return err
	}

	if rekorServer != "" {
		client, err := rekorclient.GetRekorClient(rekorServer)
		if err != nil {
			return err
		}

		verifier, err := signer.Verifier()
		if err != nil {
			return err
		}

		pubKeyBytes, err := verifier.Bytes()
		if err != nil {
			return err
		}

		b := signedBytes.Bytes()
		entry, err := rekortypes.NewProposedEntry(context.Background(), "intoto", "0.0.1", rekortypes.ArtifactProperties{
			ArtifactBytes:  b,
			PublicKeyBytes: pubKeyBytes,
		})

		if err != nil {
			return err
		}

		params := rekoreentries.NewCreateLogEntryParams()
		params.SetProposedEntry(entry)
		resp, err := client.Entries.CreateLogEntry(params)
		if err != nil {
			return err
		}

		fmt.Printf("Rekor entry added at %v%v\n", rekorServer, resp.Location)
	}

	return nil
}
