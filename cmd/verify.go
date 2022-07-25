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
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivist"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/source"
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
			return runVerify(cmd.Context(), vo)
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
func runVerify(ctx context.Context, vo options.VerifyOptions) error {
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

	artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []crypto.Hash{crypto.SHA256})
	if err != nil {
		return fmt.Errorf("failed to calculate artifact digest: %w", err)
	}

	subjects := []cryptoutil.DigestSet{artifactDigestSet}
	for _, subDigest := range vo.AdditionalSubjects {
		subjects = append(subjects, cryptoutil.DigestSet{crypto.SHA256: subDigest})
	}

	var collectionSource source.Sourcer
	memSource := source.NewMemorySource()
	for _, path := range vo.AttestationFilePaths {
		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}

	collectionSource = memSource
	if vo.ArchivistOptions.Enable {
		collectionSource = source.NewMultiSource(collectionSource, source.NewArchvistSource(archivist.New(vo.ArchivistOptions.Url)))
	}

	verifiedEvidence, err := witness.Verify(
		ctx,
		policyEnvelope,
		[]cryptoutil.Verifier{verifier},
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(collectionSource),
	)

	if err != nil {
		return fmt.Errorf("failed to verify policy: %w", err)

	}

	log.Info("Verification succeeded")
	log.Info("Evidence:")
	num := 0
	for _, stepEvidence := range verifiedEvidence {
		for _, e := range stepEvidence {
			log.Info(fmt.Sprintf("%d: %s", num, e.Reference))
			num++
		}
	}

	return nil

}
