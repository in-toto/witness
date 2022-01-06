package options

import "github.com/spf13/cobra"

type RootOptions struct {
	Config string
}

func (ro *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&ro.Config, "config", "c", ".witness.yaml", "Path to the witness config file")
}
