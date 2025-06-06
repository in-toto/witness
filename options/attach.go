// Copyright 2025 The Witness Contributors
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

import (
	"github.com/spf13/cobra"
)

// AttachOptions contains options for attaching attestations to OCI artifacts
type AttachOptions struct {
	AttestationFilePaths []string
	SkipVerification     bool   // Add skip verification option
	InputTarballPath     string // Path to the input OCI image tarball
	VerifyByTarballHash  bool   // Verify attestation against input tarball hash
}

var RequiredAttachFlags = []string{
	"attestation",
}

// AddFlags adds command line flags for the AttachOptions
func (ao *AttachOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&ao.AttestationFilePaths, "attestation", "a", []string{}, "Attestation files to attach to the Docker image")
	cmd.Flags().BoolVar(&ao.SkipVerification, "skip-verification", false, "Skip verification of attestation subjects against image digest")
	cmd.Flags().StringVarP(&ao.InputTarballPath, "input-tarball", "i", "", "Path to the input OCI image tarball (required)")
	cmd.Flags().BoolVarP(&ao.VerifyByTarballHash, "verify-by-tarball-hash", "t", false, "Verify attestation against the SHA256 hash of the input tarball file")
	cmd.MarkFlagsRequiredTogether(RequiredAttachFlags...)
}
