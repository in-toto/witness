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

type VerifyOptions struct {
	KeyPath              string
	AttestationFilePaths []string
	PolicyFilePath       string
	ArtifactFilePath     string
	RekorServer          string
	CAPath               string
	EmailContstraints    []string
}

func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&vo.KeyPath, "publickey", "k", "", "Path to the policy signer's public key")
	cmd.Flags().StringSliceVarP(&vo.AttestationFilePaths, "attestations", "a", []string{}, "Attestation files to test against the policy")
	cmd.Flags().StringVarP(&vo.PolicyFilePath, "policy", "p", "", "Path to the policy to verify")
	cmd.Flags().StringVarP(&vo.ArtifactFilePath, "artifactfile", "f", "", "Path to the artifact to verify")
	cmd.Flags().StringVarP(&vo.RekorServer, "rekor-server", "r", "", "Rekor server to fetch attestations from")
	cmd.Flags().StringVarP(&vo.CAPath, "ca", "", "", "Path to the CA certificate to use for verifying the policy")
	cmd.Flags().StringSliceVarP(&vo.EmailContstraints, "email", "", []string{}, "Email constraints to use for verifying the policy")
}
