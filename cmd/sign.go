// Copyright 2021 The TestifySec Authors
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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/witness/pkg"
)

var dataType string

var signCmd = &cobra.Command{
	Use:           "sign [file]",
	Short:         "Signs a file",
	Long:          "Signs a file with the provided key source and outputs the signed file to the specified destination",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runSign,
	Args:          cobra.ExactArgs(1),
}

func init() {
	rootCmd.AddCommand(signCmd)
	addKeyFlags(signCmd)
	signCmd.Flags().StringVarP(&dataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	signCmd.Flags().StringVarP(&outFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runSign(cmd *cobra.Command, args []string) error {
	signer, err := loadSigner()
	if err != nil {
		return err
	}

	inFilePath := args[0]
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open file to sign: %v", err)
	}

	outFile, err := loadOutfile()
	if err != nil {
		return err
	}

	defer outFile.Close()
	return witness.Sign(inFile, dataType, outFile, signer)
}
