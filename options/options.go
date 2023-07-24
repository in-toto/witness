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
	"time"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/registry"
)

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

func addFlagsFromRegistry[T any](prefix string, registrationEntries []registry.Entry[T], cmd *cobra.Command) map[string][]func(T) (T, error) {
	optSettersByName := make(map[string][]func(T) (T, error))

	for _, registration := range registrationEntries {
		for _, opt := range registration.Options {
			name := fmt.Sprintf("%s-%s-%s", prefix, registration.Name, opt.Name())
			switch optT := opt.(type) {
			case *registry.ConfigOption[T, int]:
				{
					val := cmd.Flags().Int(name, optT.DefaultVal(), opt.Description())
					optSettersByName[registration.Name] = append(optSettersByName[registration.Name], func(a T) (T, error) {
						return optT.Setter()(a, *val)
					})
				}

			case *registry.ConfigOption[T, string]:
				{
					// this is kind of a hacky solution to maintain backward compatibility with the old "-k" flag
					var val *string
					if name == "signer-file-key-path" {
						val = cmd.Flags().StringP(name, "k", optT.DefaultVal(), optT.Description())
					} else {
						val = cmd.Flags().String(name, optT.DefaultVal(), opt.Description())
					}

					optSettersByName[registration.Name] = append(optSettersByName[registration.Name], func(a T) (T, error) {
						return optT.Setter()(a, *val)
					})
				}

			case *registry.ConfigOption[T, []string]:
				{
					val := cmd.Flags().StringSlice(name, optT.DefaultVal(), opt.Description())
					optSettersByName[registration.Name] = append(optSettersByName[registration.Name], func(a T) (T, error) {
						return optT.Setter()(a, *val)
					})
				}

			case *registry.ConfigOption[T, bool]:
				{
					val := cmd.Flags().Bool(name, optT.DefaultVal(), opt.Description())
					optSettersByName[registration.Name] = append(optSettersByName[registration.Name], func(a T) (T, error) {
						return optT.Setter()(a, *val)
					})
				}

			case *registry.ConfigOption[T, time.Duration]:
				{
					val := cmd.Flags().Duration(name, optT.DefaultVal(), opt.Description())
					optSettersByName[registration.Name] = append(optSettersByName[registration.Name], func(a T) (T, error) {
						return optT.Setter()(a, *val)
					})
				}

			default:
				log.Debugf("unrecognized attestor option type: %T", optT)
			}
		}
	}

	return optSettersByName
}
