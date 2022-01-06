package options

import "github.com/spf13/cobra"

type RunOptions struct {
	KeyOptions   KeyOptions
	WorkingDir   string
	Attestations []string
	OutFilePath  string
	StepName     string
	RekorServer  string
	Tracing      bool
}

func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.KeyOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory that commands will be run from")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", []string{"Environment", "Artifact", "Git"}, "Attestations to record")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to write signed data.  Defaults to stdout")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().StringVarP(&ro.RekorServer, "rekor-server", "r", "", "Rekor server to store attestations")
	cmd.Flags().BoolVar(&ro.Tracing, "trace", false, "enable tracing for the command")
}
