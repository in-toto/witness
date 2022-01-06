package options

import "github.com/spf13/cobra"

type SignOptions struct {
	KeyOptions  KeyOptions
	DataType    string
	OutFilePath string
}

func (so *SignOptions) AddFlags(cmd *cobra.Command) {
	so.KeyOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&so.DataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	cmd.Flags().StringVarP(&so.OutFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
}
