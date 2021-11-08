package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	witness "gitlab.com/testifysec/witness-cli/pkg"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

var keyPath string
var dataType string

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
	signCmd.Flags().StringVarP(&dataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
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
	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create output file: %v", err)
	}

	defer outFile.Close()
	return witness.Sign(inFile, dataType, outFile, signer)
}
