package options

import "github.com/spf13/cobra"

type VerifyOptions struct {
	KeyPath              string
	AttestationFilePaths []string
	PolicyFilePath       string
	ArtifactFilePath     string
	ArtifactHash         string
}

func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&vo.KeyPath, "publickey", "k", "", "Path to the policy signer's public key")
	cmd.Flags().StringSliceVarP(&vo.AttestationFilePaths, "attestations", "a", []string{}, "Attestation files to test against the policy")
	cmd.Flags().StringVarP(&vo.PolicyFilePath, "policy", "p", "", "Path to the policy to verify")
	cmd.Flags().StringVarP(&vo.ArtifactFilePath, "artifactfile", "f", "", "Path to the artifact to verify")
	cmd.Flags().StringVar(&vo.ArtifactHash, "artifacthash", "", "Hash of the artifact to verify")
}
