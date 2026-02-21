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

import (
	"github.com/spf13/cobra"
)

// PolicyCmd has several subcommands for managing policies
func PolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policies",
	}
	cmd.AddCommand(
		PolicyCheckCmd(),
		PolicyGenerateCmd(),
	)
	return cmd
}

type PolicyGenerateOptions struct {
	StepNames        []string
	RootCAs          []string
	PublicKeys       []string
	Intermediates    []string
	AttestationTypes []string
	// RegoPolicies     []string
	CertCommonName []string
	CertDNSNames   []string
	CertEmails     []string
	CertOrgs       []string
	CertURIs       []string
	ArtifactsFrom  []string
	ExpiresIn      string
	OutputFile     string
}

func PolicyGenerateCmd() *cobra.Command {
	vo := PolicyGenerateOptions{}
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a policy file",
		Long: `
Example: 
	witness policy generate --step "build" --step "deploy" --root-ca "build=rootCA.pem" --root-ca "deploy=deployCA.pem" --public-key "build=buildKey.pub" --public-key "deploy=deployKey.pub"`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generatePolicy(cmd, &vo)
		},
	}
	vo.AddFlags(cmd)

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

func (vo *PolicyGenerateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&vo.StepNames, "step", []string{},
		"Name of a step to include in the policy (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&vo.RootCAs, "root-ca", []string{},
		"Root CA certificate in format 'step=file.pem' (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&vo.PublicKeys, "public-key", []string{},
		"Public key in format 'step=file.pub' (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&vo.Intermediates, "intermediate", []string{},
		"Intermediate certificate in format 'step=file.pem' (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&vo.AttestationTypes, "attestation", []string{},
		"Attestation type in format 'step=type-url' (can be specified multiple times)")
	// cmd.Flags().StringSliceVar(&vo.RegoPolicies, "rego-policy", []string{},
	// 	"Rego policy in format 'step=name=file.rego' (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&vo.CertCommonName, "cert-cn", []string{},
		"Certificate common name constraint in format 'step=commonname'")
	cmd.Flags().StringSliceVar(&vo.CertDNSNames, "cert-dns", []string{},
		"Certificate DNS name constraint in format 'step=dnsname'")
	cmd.Flags().StringSliceVar(&vo.CertEmails, "cert-email", []string{},
		"Certificate email constraint in format 'step=email'")
	cmd.Flags().StringSliceVar(&vo.CertOrgs, "cert-org", []string{},
		"Certificate organization constraint in format 'step=organization'")
	cmd.Flags().StringSliceVar(&vo.CertURIs, "cert-uri", []string{},
		"Certificate URI constraint in format 'step=uri' (useful for SPIFFE IDs)")
	cmd.Flags().StringSliceVar(&vo.ArtifactsFrom, "artifacts-from", []string{},
		"Artifact dependency in format 'step=fromStep' (can be specified multiple times)")
	cmd.Flags().StringVar(&vo.ExpiresIn, "expires-in", "720h",
		"Duration until policy expires (e.g., '720h' for 30 days, '8760h' for 1 year)")
	cmd.Flags().StringVarP(&vo.OutputFile, "output", "o", "policy.json",
		"Output file path for the generated policy")
}
