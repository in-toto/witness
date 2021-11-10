package cmd

import (
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

var keyPath string

var rootCmd = &cobra.Command{
	Use:   "witness",
	Short: "Collect and verify attestations about your build environments",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "Path to the signing key")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

func loadSigner() (crypto.Signer, error) {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	signer, err := crypto.NewSignerFromReader(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}

	return signer, nil
}

func loadOutfile() (*os.File, error) {
	var err error
	out := os.Stdout
	if outFilePath != "" {
		out, err = os.Create(outFilePath)
		if err != nil {
			return nil, fmt.Errorf("could not create output file: %v", err)
		}
	}

	return out, err
}
