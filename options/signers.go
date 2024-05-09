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
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/spf13/cobra"
)

type SignerOptions map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)

func (so *SignerOptions) AddFlags(cmd *cobra.Command) {
	signerRegistrations := signer.RegistryEntries()
	*so = addFlagsFromRegistry("signer", signerRegistrations, cmd)
}

type KMSSignerProviderOptions map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)

func (ko *KMSSignerProviderOptions) AddFlags(cmd *cobra.Command) {
	kmsProviderOpts := kms.ProviderOptions()
	for k := range kmsProviderOpts {
		if kmsProviderOpts[k] != nil {
			*ko = addFlags("signer", kmsProviderOpts[k].ProviderName(), kmsProviderOpts[k].Init(), *ko, cmd)
		}
	}
}
