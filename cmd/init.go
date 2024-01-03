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
	"github.com/spf13/cobra"
)

const (
	defaultPath = "template.witness.yml"
)

func InitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "init",
		Short:                 "Generate a template configuration file with empty values.",
		Long:                  "Generate a template configuration file with empty values. The output file path can be specified as an argument, otherwise a default path of 'template.witness.yml' will be used.",
		DisableFlagsInUseLine: true,
		DisableAutoGenTag:     true,
		Args:                  cobra.MatchAll(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			if len(args) == 0 {
				path = defaultPath
			} else {
				path = args[0]
			}

			if err := GenConfig(New(), path); err != nil {
				return err
			}
			return nil
		},
	}
	return cmd
}
