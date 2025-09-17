// Copyright 2025 The Witness Contributors
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
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/oci"
	"github.com/in-toto/witness/options"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/spf13/cobra"
)

func AttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Provides utilities for attaching artifacts to other artifacts in a registry",
	}

	cmd.AddCommand(
		attachAttestationCmd(),
	)

	return cmd
}

// sbom
// signature
// attestation - in-toto
func attachAttestationCmd() *cobra.Command {
	o := &options.AttachAttestationOptions{}
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Attach attestation to the supplied container image",
		Example: `  witness attach attestation --attestation <attestation file path> <image uri>

  # attach attestations from multiple files to a container image
  witness attach attestation --attestation <attestation file path> --attestation <attestation file path> <image uri>

  # attach attestation from bundle files in form of JSONLines to a container image
  # https://github.com/in-toto/attestation/blob/main/spec/v1.0-draft/bundle.md
  witness attach attestation --attestation <attestation bundle file path> <image uri>
`,
		Args:              cobra.MinimumNArgs(1),
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return AttestationCmd(cmd.Context(), o.Registry, o.Attestations, args[0])
		},
	}
	o.AddFlags(cmd)
	return cmd
}

func AttestationCmd(ctx context.Context, regOpts oci.RegistryOptions, signedPayloads []string, imageRef string) error {
	ociremoteOptions, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	for _, payload := range signedPayloads {
		if err := attachAttestation(ociremoteOptions, payload, imageRef, regOpts.NameOptions()); err != nil {
			return fmt.Errorf("attaching payload from %s: %w", payload, err)
		}
	}
	return nil
}

func attachAttestation(remoteOpts []oci.Option, signedPayload, imageRef string, nameOpts []name.Option) error {
	log.Info("Opening attestation file:", signedPayload)
	attestationFile, err := os.Open(signedPayload)
	if err != nil {
		return err
	}
	defer attestationFile.Close()
	env := dsse.Envelope{}
	decoder := json.NewDecoder(attestationFile)
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}
		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if env.PayloadType != types.IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
		}
		if len(env.Signatures) == 0 {
			return fmt.Errorf("could not attach attestation without having signatures")
		}

		ref, err := name.ParseReference(imageRef, nameOpts...)
		if err != nil {
			return err
		}
		if _, ok := ref.(name.Digest); !ok {
			log.Warnf("image reference %s uses a tag, not a digest, to identify the image to sign. This can lead you to sign a different image than the intended one.", imageRef)
		}
		digest, err := oci.ResolveDigest(ref, remoteOpts...)
		if err != nil {
			return err
		}
		// Overwrite "ref" with a digest to avoid a race where we use a tag
		// multiple times, and it potentially points to different things at
		// each access.
		ref = digest // nolint
		log.Info("Creating attestation with DSSE payload")
		opts := []oci.StaticOption{oci.WithLayerMediaType(types.DssePayloadType)}
		att, err := oci.NewAttestation(payload, opts...)
		if err != nil {
			return err
		}
		log.Info("Fetching signed entity for:", digest.String())
		se, err := oci.SignedEntity(digest, remoteOpts...)
		if err != nil {
			log.Errorf("failed to fetch signed entity for %s: %w", ref, err)
			return err
		}
		if se == nil {
			return fmt.Errorf("no signed entity returned for %s", ref)
		}
		log.Info("Attaching attestation to signed entity")
		newSE, err := oci.AttachAttestationToEntity(se, att)
		if err != nil {
			return err
		}
		log.Info("Writing attestation to repository:", digest.Repository.String())
		err = oci.WriteAttestations(digest.Repository, newSE, remoteOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}
