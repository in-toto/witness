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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
)

func SignCmd() *cobra.Command {
	so := options.SignOptions{}
	cmd := &cobra.Command{
		Use:               "sign [file]",
		Short:             "Signs a file",
		Long:              "Signs a file with the provided key source and outputs the signed file to the specified destination",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(so)
		},
	}

	so.AddFlags(cmd)
	return cmd
}

func runSign(so options.SignOptions) error {
	signers, errors := getSigners(so.KeyOptions)

	if len(errors) > 0 {
		return fmt.Errorf("%v", errors)
	}

	if len(signers) == 0 {
		return fmt.Errorf("no signers found")
	}

	inFile, err := os.Open(so.InFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	defer inFile.Close()

	outFile, err := loadOutfile(so.OutFilePath)
	if err != nil {
		return err
	}

	defer outFile.Close()

	return witness.Sign(inFile, so.DataType, outFile, signers...)
}
