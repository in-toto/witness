package options

import "github.com/spf13/cobra"

type KeyOptions struct {
	KeyPath           string
	CertPath          string
	IntermediatePaths []string
	SpiffePath        string
}

func (ko *KeyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&ko.KeyPath, "key", "k", "", "Path to the signing key")
	cmd.Flags().StringVar(&ko.CertPath, "certificate", "", "Path to the signing key's certificate")
	cmd.Flags().StringSliceVarP(&ko.IntermediatePaths, "intermediates", "i", []string{}, "Intermediates that link trust back to a root in the policy")
	cmd.Flags().StringVar(&ko.SpiffePath, "spiffe-socket", "", "Path to the SPIFFE Workload API socket")
}
