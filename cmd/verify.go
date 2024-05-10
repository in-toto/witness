// Copyright 2021-2024 The Witness Contributors
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
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/go-witness/timestamp"
	archivista_client "github.com/in-toto/witness/internal/archivista"
	"github.com/in-toto/witness/internal/policy"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{
		ArchivistaOptions:          options.ArchivistaOptions{},
		KMSVerifierProviderOptions: options.KMSVerifierProviderOptions{},
		VerifierOptions:            options.VerifierOptions{},
	}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Lookup("policy-ca").Changed {
				log.Warn("The flag `--policy-ca` is deprecated and will be removed in a future release. Please use `--policy-ca-root` and `--policy-ca-intermediate` instead.")
			}

			verifiers, err := loadVerifiers(cmd.Context(), vo.VerifierOptions, vo.KMSVerifierProviderOptions, providersFromFlags("verifier", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}
			return runVerify(cmd.Context(), vo, verifiers...)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

const (
	MAX_DEPTH = 4
)

// todo: this logic should be broken out and moved to pkg/
// we need to abstract where keys are coming from, etc
func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers ...cryptoutil.Verifier) error {
	var (
		collectionSource source.Sourcer
		archivistaClient *archivista.Client
	)
	memSource := source.NewMemorySource()

	collectionSource = memSource
	if vo.ArchivistaOptions.Enable {
		archivistaClient = archivista.New(vo.ArchivistaOptions.Url)
		collectionSource = source.NewMultiSource(collectionSource, source.NewArchvistSource(archivistaClient))
	}

	if vo.KeyPath == "" && len(vo.PolicyCARootPaths) == 0 && len(verifiers) == 0 {
		return fmt.Errorf("must supply either a public key, CA certificates or a verifier")
	}

	if vo.KeyPath != "" {
		keyFile, err := os.Open(vo.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to open key file: %w", err)
		}
		defer keyFile.Close()

		v, err := cryptoutil.NewVerifierFromReader(keyFile)
		if err != nil {
			return fmt.Errorf("failed to create verifier: %w", err)
		}

		verifiers = append(verifiers, v)
	}

	var policyRoots []*x509.Certificate
	if len(vo.PolicyCARootPaths) > 0 {
		for _, caPath := range vo.PolicyCARootPaths {
			caFile, err := os.ReadFile(caPath)
			if err != nil {
				return fmt.Errorf("failed to read root CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(caFile)
			if err != nil {
				return fmt.Errorf("failed to parse root CA certificate: %w", err)
			}

			policyRoots = append(policyRoots, cert)
		}
	}

	var policyIntermediates []*x509.Certificate
	if len(vo.PolicyCAIntermediatePaths) > 0 {
		for _, caPath := range vo.PolicyCAIntermediatePaths {
			caFile, err := os.ReadFile(caPath)
			if err != nil {
				return fmt.Errorf("failed to read intermediate CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(caFile)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
			}

			policyRoots = append(policyIntermediates, cert)
		}
	}

	ptsVerifiers := make([]timestamp.TimestampVerifier, 0)
	if len(vo.PolicyTimestampServers) > 0 {
		for _, server := range vo.PolicyTimestampServers {
			f, err := os.ReadFile(server)
			if err != nil {
				return fmt.Errorf("failed to open Timestamp Server CA certificate file: %w", err)
			}

			cert, err := cryptoutil.TryParseCertificate(f)
			if err != nil {
				return fmt.Errorf("failed to parse Timestamp Server CA certificate: %w", err)
			}

			ptsVerifiers = append(ptsVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts([]*x509.Certificate{cert})))
		}
	}

	policyEnvelope, err := policy.LoadPolicy(ctx, vo.PolicyFilePath, archivista_client.NewArchivistaClient(vo.ArchivistaOptions.Url, archivistaClient))
	if err != nil {
		return fmt.Errorf("failed to open policy file: %w", err)
	}

	subjects := []cryptoutil.DigestSet{}
	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}

		subjects = append(subjects, artifactDigestSet)
	}

	for _, subDigest := range vo.AdditionalSubjects {
		subjects = append(subjects, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: subDigest})
	}

	if len(subjects) == 0 {
		return errors.New("at least one subject is required, provide an artifact file or subject")
	}

	for _, path := range vo.AttestationFilePaths {
		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	verifiedResult, err := witness.Verify(
		ctx,
		policyEnvelope,
		verifiers,
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(collectionSource),
		witness.VerifyWithPolicyTimestampAuthorities(ptsVerifiers),
		witness.VerifyWithPolicyCARoots(policyRoots),
		witness.VerifyWithPolicyCAIntermediates(policyIntermediates),
		witness.VerifyWithPolicyCertConstraints(vo.PolicyCommonName, vo.PolicyDNSNames, vo.PolicyEmails, vo.PolicyOrganizations, vo.PolicyURIs),
	)
	if err != nil {
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	log.Info("Verification succeeded")
	log.Infof("Evidence:")
	num := 0
	for _, stepEvidence := range verifiedResult.StepResults {
		for _, e := range stepEvidence.Passed {
			log.Info(fmt.Sprintf("%d: %s", num, e.Reference))
			num++
		}
	}

	return nil
}
