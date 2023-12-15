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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func initConfig(rootCmd *cobra.Command, rootOptions *options.RootOptions) error {
	v := viper.New()
	if _, err := os.Stat(rootOptions.Config); errors.Is(err, os.ErrNotExist) {
		if rootCmd.Flags().Lookup("config").Changed {
			return fmt.Errorf("config file %s does not exist", rootOptions.Config)
		} else {
			log.Debugf("%s does not exist, using command line arguments", rootOptions.Config)
			return nil
		}
	}

	v.SetConfigFile(rootOptions.Config)
	if v.ConfigFileUsed() != "" {
		log.Infof("Using config file: %v", v.ConfigFileUsed())
	}

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	//Currently we do not accept configuration for root commands
	commands := rootCmd.Commands()
	for _, cm := range commands {
		//Check which command we are running
		if !contains(os.Args, cm.Name()) {
			continue
		}

		flags := cm.Flags()
		flags.VisitAll(func(f *pflag.Flag) {
			configKey := fmt.Sprintf("%s.%s", cm.Name(), f.Name)
			if !f.Changed {
				if f.Value.Type() == "stringSlice" {
					configValue := v.GetStringSlice(configKey)
					if len(configValue) > 0 {
						configValueStr := strings.Join(configValue, ",")
						if err := flags.Set(f.Name, configValueStr); err != nil {
							log.Errorf("failed to set config value: %w", err)
						}
					}
				} else {
					configValue := v.GetString(configKey)
					if configValue != "" {
						if err := flags.Set(f.Name, configValue); err != nil {
							log.Errorf("failed to set config value: %w", err)
						}
					}
				}
			}
		})
	}

	return nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
