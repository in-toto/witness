package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
)

var keyPath string
var outputFormat string

var signCmd = &cobra.Command{
	Use:           "sign [FILE] [OUTFILE]",
	Short:         "Signs a file",
	Long:          "Signs a file with the provided key source and outputs the signed file to the specified destination",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runSign,
	Args:          cobra.ExactArgs(2),
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to the signing key")
	signCmd.Flags().StringVarP(&outputFormat, "output-format", "f", "dsse", "Format of the output file, valid options: dsse")
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runSign(cmd *cobra.Command, args []string) error {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	signer, err := crypto.NewSignerFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	inFilePath, outFilePath := args[0], args[1]
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open file to sign: %v", err)
	}

	defer inFile.Close()
	inFileBytes, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("could not read file to sign: %v", err)
	}

	envelope, err := dsse.Sign("https://witness.testifysec.com/signeddata/v0.1", inFileBytes, signer)
	if err != nil {
		return fmt.Errorf("failed to sign data: %v", err)
	}

	envelopeJson, err := json.Marshal(&envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal dsse envelope to json: %v", err)
	}

	err = os.WriteFile(outFilePath, envelopeJson, 0644)
	if err != nil {
		return fmt.Errorf("failed to write signed file: %v", err)
	}

	return nil
}
