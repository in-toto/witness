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

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/registry"
	"github.com/testifysec/go-witness/signer"
)

type SignerOptions map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)

func (so SignerOptions) AddFlags(cmd *cobra.Command) {
	signerRegistrations := signer.RegistryEntries()
	for _, registration := range signerRegistrations {
		for _, opt := range registration.Options {
			name := fmt.Sprintf("signer-%s-%s", registration.Name, opt.Name())
			switch optT := opt.(type) {
			case *registry.ConfigOption[signer.SignerProvider, int]:
				{
					val := cmd.Flags().Int(name, optT.DefaultVal(), opt.Description())
					so[registration.Name] = append(so[registration.Name], func(sp signer.SignerProvider) (signer.SignerProvider, error) {
						return optT.Setter()(sp, *val)
					})
				}

			case *registry.ConfigOption[signer.SignerProvider, string]:
				{
					// this is kind of a hacky solution to maintain backward compatibility with the old "-k" flag
					var val *string
					if name == "signer-file-key-path" {
						val = cmd.Flags().StringP(name, "k", optT.DefaultVal(), optT.Description())
					} else {
						val = cmd.Flags().String(name, optT.DefaultVal(), opt.Description())
					}

					so[registration.Name] = append(so[registration.Name], func(sp signer.SignerProvider) (signer.SignerProvider, error) {
						return optT.Setter()(sp, *val)
					})
				}

			case *registry.ConfigOption[signer.SignerProvider, []string]:
				{
					val := cmd.Flags().StringSlice(name, optT.DefaultVal(), opt.Description())
					so[registration.Name] = append(so[registration.Name], func(sp signer.SignerProvider) (signer.SignerProvider, error) {
						return optT.Setter()(sp, *val)
					})
				}

			case *registry.ConfigOption[signer.SignerProvider, bool]:
				{
					val := cmd.Flags().Bool(name, optT.DefaultVal(), opt.Description())
					so[registration.Name] = append(so[registration.Name], func(sp signer.SignerProvider) (signer.SignerProvider, error) {
						return optT.Setter()(sp, *val)
					})
				}

			default:
				log.Debugf("unrecognized signer option type: %T", optT)
			}
		}
	}
}
