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
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/witness/oci"
	"github.com/spf13/cobra"
)

// AttachAttestationOptions is the top level wrapper for the attach attestation command.
type AttachAttestationOptions struct {
	Attestations     []string
	SkipVerification bool // Add skip verification option
	Registry         oci.RegistryOptions
	AuthConfig       authn.AuthConfig
}
type Option func(*options)

type options struct {
	AttestationSuffix string
	TargetRepository  name.Repository
	ROpt              []remote.Option
	NameOpts          []name.Option
	OriginalOptions   []Option
}

const AttestationTagSuffix = "att"

// AddFlags implements Interface
func (o *AttachAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringArrayVarP(&o.Attestations, "attestation", "", nil,
		"path to the attestation envelope")
	// cmd.Flags().BoolVar(&o.SkipVerification, "skip-verification", false, "Skip verification of attestation subjects against image digest. Don't use this for anything but testing")
}
