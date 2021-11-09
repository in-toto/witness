package cmd

import (
	"bytes"
	"encoding/json"

	"github.com/spf13/cobra"
	witness "gitlab.com/testifysec/witness-cli/pkg"
	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/run"
)

var workingDir string
var attestations []string
var outFilePath string

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
	runCmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to the signing key")
	runCmd.Flags().StringVarP(&workingDir, "workingdir", "d", "", "Directory that commands will be run from")
	runCmd.Flags().StringArrayVarP(&attestations, "attestations", "a", []string{"CommandRun"}, "Attestations to record")
	runCmd.Flags().StringVarP(&outFilePath, "outfile", "o", "", "File to write signed data.  If no file is provided data will be printed to stdout")
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

	collection := attestation.NewCollection(attestors)
	data, err := json.Marshal(&collection)
	if err != nil {
		return err
	}

	dataReader := bytes.NewReader(data)
	return witness.Sign(dataReader, attestation.CollectionDataType, out, signer)
}
