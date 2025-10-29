// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import "github.com/spf13/cobra"

// PolicyCmd has several subcommands for managing policies
func PolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policies",
	}
	cmd.AddCommand(
		PolicyCheckCmd(),
	)
	return cmd
}

// PolicyValidateCmd validates a policy
func PolicyCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "check [policy file]",
		Short:             "Check a policy file",
		Long:              `Check a policy file for correctness and expiration.`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Args:              cobra.MinimumNArgs(1), // Requires at least one argument
		RunE: func(cmd *cobra.Command, args []string) error {
			return checkPolicy(cmd, args)
		},
	}

	cmd.Flags().BoolP("verbose", "v", false, "Show detailed validation progress")
	cmd.Flags().BoolP("quiet", "q", false, "Only show errors, no success messages")
	cmd.Flags().Bool("json", false, "Output results in JSON format")

	return cmd
}
