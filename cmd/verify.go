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
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	witness "github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/rekor"
	"github.com/testifysec/witness/options"
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
			return runVerify(cmd.Context(), vo, args)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

const (
	MAX_DEPTH = 4
)

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(ctx context.Context, vo options.VerifyOptions, args []string) error {
	if vo.KeyPath == "" && len(vo.CAPaths) == 0 {
		return fmt.Errorf("must suply public key or ca paths")
	}

	var verifier cryptoutil.Verifier

	if vo.KeyPath != "" {
		keyFile, err := os.Open(vo.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to open key file: %w", err)
		}
		defer keyFile.Close()

		verifier, err = cryptoutil.NewVerifierFromReader(keyFile)
		if err != nil {
			return fmt.Errorf("failed to create verifier: %w", err)
		}

	}

	inFile, err := os.Open(vo.PolicyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file to sign: %v", err)
	}

	defer inFile.Close()
	policyEnvelope := dsse.Envelope{}
	decoder := json.NewDecoder(inFile)
	if err := decoder.Decode(&policyEnvelope); err != nil {
		return fmt.Errorf("could not unmarshal policy envelope: %w", err)
	}

	diskEnvs, err := loadEnvelopesFromDisk(vo.AttestationFilePaths)
	if err != nil {
		return fmt.Errorf("failed to load attestation files: %w", err)
	}

	verifiedEvidence := []witness.CollectionEnvelope{}

	if vo.RekorServer != "" {

		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact file's hash: %w", err)
		}

		rc, err := rekor.New(vo.RekorServer)
		if err != nil {
			return fmt.Errorf("failed to get initialize Rekor client: %w", err)
		}

		digestSets := []cryptoutil.DigestSet{}
		digestSets = append(digestSets, artifactDigestSet)

		verifiers := []cryptoutil.Verifier{}
		verifiers = append(verifiers, verifier)

		evidence, err := rc.FindEvidence(digestSets, policyEnvelope, verifiers, diskEnvs, MAX_DEPTH)
		if err != nil {
			return fmt.Errorf("failed to find evidence: %w", err)
		}

		verifiedEvidence = append(verifiedEvidence, evidence...)
	}

	if vo.RekorServer == "" {
		verifiedEvidence, err = witness.Verify(policyEnvelope, []cryptoutil.Verifier{verifier}, witness.VerifyWithCollectionEnvelopes(diskEnvs))
		if err != nil {
			return fmt.Errorf("failed to verify policy: %w", err)

		}
	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	for i, e := range verifiedEvidence {
		log.Info(fmt.Sprintf("%d: %s", i, e.Reference))
	}
	return nil

}

func loadEnvelopesFromDisk(paths []string) ([]witness.CollectionEnvelope, error) {
	envelopes := make([]witness.CollectionEnvelope, 0)
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

		h := sha256.Sum256(fileBytes)

		collectionEnv := witness.CollectionEnvelope{
			Envelope:  env,
			Reference: fmt.Sprintf("sha256:%x  %s", h, path),
		}

		envelopes = append(envelopes, collectionEnv)
	}

	return envelopes, nil
}
