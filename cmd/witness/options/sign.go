// Copyright 2022 The Witness Contributors
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

package options

import "github.com/spf13/cobra"

type SignOptions struct {
	KeyOptions  KeyOptions
	DataType    string
	OutFilePath string
	InFilePath  string
	// FulcioURL    string
	// OIDCIssuer   string
	// OIDCClientID string
}

func (so *SignOptions) AddFlags(cmd *cobra.Command) {
	so.KeyOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&so.DataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	cmd.Flags().StringVarP(&so.OutFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
	cmd.Flags().StringVarP(&so.InFilePath, "infile", "f", "", "Witness policy file to sign")
	// cmd.Flags().StringVarP(&so.FulcioURL, "fulcio", "", "https://v1.fulcio.sigstore.dev", "Fulcio address to sign with")
	// cmd.Flags().StringVarP(&so.OIDCIssuer, "oidc-issuer", "", "https://oauth2.sigstore.dev/auth", "OIDC issuer to use for authentication")
	// cmd.Flags().StringVarP(&so.OIDCClientID, "oidc-client-id", "", "sigstore", "OIDC client ID to use for authentication")
}
