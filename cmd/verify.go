package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	witness "gitlab.com/testifysec/witness-cli/pkg"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

var verifyCmd = &cobra.Command{
	Use:           "verify [FILE]",
	Short:         "Verifies a signed file",
	Long:          "Verifies a signed file with the provided key source and exits with code 0 if verification succeeds",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runVerify,
	Args:          cobra.ExactArgs(1),
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to the signing key")
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(cmd *cobra.Command, args []string) error {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	verifier, err := crypto.NewVerifierFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	inFilePath := args[0]
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open file to sign: %v", err)
	}

	defer inFile.Close()
	return witness.Verify(inFile, verifier)
}
