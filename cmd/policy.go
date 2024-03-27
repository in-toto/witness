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
		Use:   "check [policy file]",
		Short: "Check a policy file",
		Long:  `Check a policy file for correctness and expiration.`,
		Args:  cobra.MinimumNArgs(1), // Requires at least one argument
		RunE:  checkPolicy,
	}

	return cmd
}
