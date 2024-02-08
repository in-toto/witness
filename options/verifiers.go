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

import (
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/spf13/cobra"
)

type VerifierOptions map[string][]func(signer.VerifierProvider) (signer.VerifierProvider, error)

func (vo *VerifierOptions) AddFlags(cmd *cobra.Command) {
	verifierRegistrations := signer.VerifierRegistryEntries()
	*vo = addFlagsFromRegistry("verifier", verifierRegistrations, cmd)
}

type KMSVerifierProviderOptions map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)

func (ko *KMSVerifierProviderOptions) AddFlags(cmd *cobra.Command) {
	kmsProviderOpts := kms.ProviderOptions()
	for k, v := range kmsProviderOpts {
		if v != nil {
			opts := v.Init()
			name := fmt.Sprintf("kms-%s", strings.TrimSuffix(k, "kms://"))
			// NOTE: this strikes me as a bad idea since it isn't a registry entry. however we wish to piggy back on the add flags logic, and when splitting it out I got errors
			entry := []registry.Entry[signer.SignerProvider]{
				{
					Name:    name,
					Options: opts,
				},
			}
			*ko = addFlagsFromRegistry[signer.SignerProvider]("signer", entry, cmd)
		}
	}
}
