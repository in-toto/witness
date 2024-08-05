// Copyright 2022 The Witness Contributors
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

package options

import (
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/spf13/cobra"
)

type VerifyOptions struct {
	ArchivistaOptions          ArchivistaOptions
	VerifierOptions            VerifierOptions
	KMSVerifierProviderOptions KMSVerifierProviderOptions
	KeyPath                    string
	AttestationFilePaths       []string
	PolicyFilePath             string
	ArtifactFilePath           string
	ArtifactDirectoryPath      string
	AdditionalSubjects         []string
	PolicyFulcioCertExtensions certificate.Extensions
	PolicyCARootPaths          []string
	PolicyCAIntermediatePaths  []string
	PolicyTimestampServers     []string
	PolicyCommonName           string
	PolicyDNSNames             []string
	PolicyEmails               []string
	PolicyOrganizations        []string
	PolicyURIs                 []string
}

var RequiredVerifyFlags = []string{
	"policy",
}

var OneRequiredPKVerifyFlags = []string{
	"publickey",
	"policy-ca",
	"policy-ca-roots",
	"policy-ca-intermediates",
	"verifier-kms-ref",
}

var OneRequiredSubjectFlags = []string{
	"artifactfile",
	"subjects",
}

func (vo *VerifyOptions) AddFlags(cmd *cobra.Command) {
	vo.VerifierOptions.AddFlags(cmd)
	vo.ArchivistaOptions.AddFlags(cmd)
	vo.KMSVerifierProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&vo.KeyPath, "publickey", "k", "", "Path to the policy signer's public key")
	cmd.Flags().StringSliceVarP(&vo.AttestationFilePaths, "attestations", "a", []string{}, "Attestation files to test against the policy")
	cmd.Flags().StringVarP(&vo.PolicyFilePath, "policy", "p", "", "Path to the policy to verify")
	cmd.Flags().StringVarP(&vo.ArtifactFilePath, "artifactfile", "f", "", "Path to the artifact subject to verify")
	cmd.Flags().StringVarP(&vo.ArtifactDirectoryPath, "directory-path", "", "", "Path to the directory subject to verify")
	cmd.Flags().StringSliceVarP(&vo.AdditionalSubjects, "subjects", "s", []string{}, "Additional subjects to lookup attestations")
	cmd.Flags().StringSliceVarP(&vo.PolicyCARootPaths, "policy-ca-roots", "", []string{}, "Paths to CA root certificates to use for verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyCAIntermediatePaths, "policy-ca-intermediates", "", []string{}, "Paths to CA intermediate certificates to use for verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyTimestampServers, "policy-timestamp-servers", "", []string{}, "Paths to the CA certificates for Timestamp Authority Servers to use when verifying policy signed with x.509")
	cmd.Flags().StringVar(&vo.PolicyCommonName, "policy-commonname", "*", "The common name to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyDNSNames, "policy-dns-names", []string{"*"}, "The DNS names to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyEmails, "policy-emails", []string{"*"}, "The DNS names to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyOrganizations, "policy-organizations", []string{"*"}, "The organizations to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVar(&vo.PolicyURIs, "policy-uris", []string{"*"}, "The URIs to use when verifying a policy signed with x.509")
	cmd.Flags().StringSliceVarP(&vo.PolicyCARootPaths, "policy-ca", "", []string{}, "Paths to CA certificates to use for verifying the policy (deprecated: use --policy-ca-roots instead)")

	// -- Fulcio Cert extensions begin --
	// Source: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.Issuer, "policy-fulcio-oidc-issuer", "",
		"The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.")

	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.BuildTrigger, "policy-fulcio-build-trigger", "",
		"Event or action that initiated the build.")

	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryDigest, "policy-fulcio-source-repository-digest", "",
		"Immutable reference to a specific version of the source code that the build was based upon.")

	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.RunInvocationURI, "policy-fulcio-run-invocation-uri", "",
		"Run Invocation URL to uniquely identify the build execution.")

	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryIdentifier, "policy-fulcio-source-repository-identifier", "",
		"Immutable identifier for the source repository the workflow was based upon.")

	cmd.Flags().StringVar(&vo.PolicyFulcioCertExtensions.SourceRepositoryRef, "policy-fulcio-source-repository-ref", "",
		"Source Repository Ref that the build run was based upon.")
	// -- Fulcio Cert extensions end --

	cmd.MarkFlagsRequiredTogether(RequiredVerifyFlags...)
	cmd.MarkFlagsOneRequired(OneRequiredPKVerifyFlags...)
	cmd.MarkFlagsOneRequired(OneRequiredSubjectFlags...)
}
