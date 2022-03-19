// Copyright 2021 The Witness Contributors
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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/testifysec/witness/cmd/witness/options"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/rekor"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(vo, args)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

func runVerify(vo options.VerifyOptions, args []string) error {
	verifiers := []cryptoutil.Verifier{}

	errors := []error{}

	//Policy Public Key Verifier
	if vo.KeyPath != "" {
		verifier, err := fileVerifier(vo.KeyPath)
		if err != nil {
			errors = append(errors, err)
		} else {
			verifiers = append(verifiers, verifier)
		}
	}

	//Polcy CA Verifier
	if len(vo.CAPaths) > 0 {
		verifier, err := caVerifier(vo.CAPaths)
		if err != nil {
			errors = append(errors, err...)
		} else {
			verifiers = append(verifiers, verifier)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to load policy verifiers: %v", errors)
	}

	//Load Policy
	policyFile, err := os.Open(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	defer policyFile.Close()
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(policyFile)
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return fmt.Errorf("could not unmarshal policy envelope: %w", err)
	}

	//Load Envelopes
	envelopes := make([]dsse.Envelope, 0)
	diskEnvs, err := loadEnvelopesFromDisk(vo.AttestationFilePaths)
	if err != nil {
		return fmt.Errorf("failed to load attestation files: %w", err)
	}

	envelopes = append(envelopes, diskEnvs...)
	if vo.RekorServer != "" {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact file's hash: %w", err)
		}

		rekorEnvs, err := loadEnvelopesFromRekor(vo.RekorServer, artifactDigestSet)
		if err != nil {
			return err
		}

		envelopes = append(envelopes, rekorEnvs...)
	}

	return witness.Verify(policyEnvelope, verifiers, witness.VerifyWithCollectionEnvelopes(envelopes))
}

func loadEnvelopesFromDisk(paths []string) ([]dsse.Envelope, error) {
	envelopes := make([]dsse.Envelope, 0)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		defer file.Close()
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			continue
		}

		env := dsse.Envelope{}
		if err := json.Unmarshal(fileBytes, &env); err != nil {
			continue
		}
		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}

func loadEnvelopesFromRekor(rekorServer string, artifactDigestSet cryptoutil.DigestSet) ([]dsse.Envelope, error) {
	envelopes := make([]dsse.Envelope, 0)
	rc, err := rekor.New(rekorServer)
	if err != nil {
		return nil, fmt.Errorf("failed to get initialize Rekor client: %w", err)
	}

	entries, err := rc.FindEntriesBySubject(artifactDigestSet)
	if err != nil {
		return nil, fmt.Errorf("failed to find any entries in rekor: %w", err)
	}

	for _, entry := range entries {
		env, err := rekor.ParseEnvelopeFromEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dsse envelope from rekor entry: %w", err)
		}

		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}

func caVerifier(caPaths []string) (cryptoutil.Verifier, []error) {
	caCerts := make([]*x509.Certificate, 0)
	errors := []error{}

	for _, caPath := range caPaths {
		caCert, err := pemutil.LoadCertificate(caPath)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		caCerts = append(caCerts, caCert)
	}

	if len(caCerts) == 0 {
		return nil, errors
	}

	return cryptoutil.NewCAVerifier(caCerts), nil
}

func fileVerifier(keyPath string) (cryptoutil.Verifier, error) {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %v", err)
	}

	defer keyFile.Close()

	return cryptoutil.NewVerifierFromReader(keyFile)
}
