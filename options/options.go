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

	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/spf13/cobra"
)

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

func addFlags[T any](prefix string, regName string, options []registry.Configurer, optSettersMap map[string][]func(T) (T, error), cmd *cobra.Command) map[string][]func(T) (T, error) {
	for _, opt := range options {
		name := fmt.Sprintf("%s-%s-%s", prefix, regName, opt.Name())
		switch optT := opt.(type) {
		case *registry.ConfigOption[T, int]:
			{
				val := cmd.Flags().Int(name, optT.DefaultVal(), opt.Description())
				optSettersMap[regName] = append(optSettersMap[regName], func(a T) (T, error) {
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

				optSettersMap[regName] = append(optSettersMap[regName], func(a T) (T, error) {
					return optT.Setter()(a, *val)
				})
			}

		case *registry.ConfigOption[T, []string]:
			{
				val := cmd.Flags().StringSlice(name, optT.DefaultVal(), opt.Description())
				optSettersMap[regName] = append(optSettersMap[regName], func(a T) (T, error) {
					return optT.Setter()(a, *val)
				})
			}

		case *registry.ConfigOption[T, bool]:
			{
				val := cmd.Flags().Bool(name, optT.DefaultVal(), opt.Description())
				optSettersMap[regName] = append(optSettersMap[regName], func(a T) (T, error) {
					return optT.Setter()(a, *val)
				})
			}

		case *registry.ConfigOption[T, time.Duration]:
			{
				val := cmd.Flags().Duration(name, optT.DefaultVal(), opt.Description())
				optSettersMap[regName] = append(optSettersMap[regName], func(a T) (T, error) {
					return optT.Setter()(a, *val)
				})
			}

		default:
			log.Debugf("unrecognized attestor option type: %T", optT)
		}
	}

	return optSettersMap
}

func addFlagsFromRegistry[T any](prefix string, registrationEntries []registry.Entry[T], cmd *cobra.Command) map[string][]func(T) (T, error) {
	optSettersByName := make(map[string][]func(T) (T, error))

	for _, registration := range registrationEntries {
		addFlags(prefix, registration.Name, registration.Options, optSettersByName, cmd)
	}

	return optSettersByName
}
