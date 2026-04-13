// Copyright 2024 The Witness Contributors
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

func AttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attach",
		Short:             "Attach attestations to OCI images",
		Long:              "Attach attestations as OCI referrers to container images in a registry",
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(AttestationCmd())
	return cmd
}

func AttestationCmd() *cobra.Command {
	ao := options.AttachOptions{}

	cmd := &cobra.Command{
		Use:               "attestation [attestation-files]...",
		Short:             "Attach an attestation file as an OCI referrer",
		Long:              "Attach one or more attestation JSON files as OCI referrers to a container image in a registry",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Args:              cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttachAttestation(cmd.Context(), ao, args)
		},
	}

	ao.AddFlags(cmd)
	return cmd
}

// Minimal in-toto statement struct for parsing subjects
type IntotoStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

func runAttachAttestation(ctx context.Context, ao options.AttachOptions, attestationFiles []string) error {
	imageRef := ao.ImageURI
	if imageRef == "" {
		return fmt.Errorf("--image-uri flag is required")
	}

	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	var originalDigest v1.Hash

	// Get the original image descriptor from the registry
	originalImage, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		if _, errIndex := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)); errIndex == nil {
			originalDesc, errHead := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
			if errHead != nil {
				return fmt.Errorf("failed to fetch image/index from registry: %w", errHead)
			}
			originalDigest = originalDesc.Digest
		} else {
			return fmt.Errorf("failed to fetch image from registry: %w", err)
		}
	} else {
		originalDigest, err = originalImage.Digest()
		if err != nil {
			return fmt.Errorf("failed to get original image digest: %w", err)
		}
	}

	return attachToSubject(ctx, ao, ref, originalDigest, attestationFiles)
}

func attachToSubject(ctx context.Context, ao options.AttachOptions, ref name.Reference, subjectDigest v1.Hash, attestationFiles []string) error {
	for _, attestPath := range attestationFiles {
		attestData, err := os.ReadFile(attestPath)
		if err != nil {
			return fmt.Errorf("failed to read attestation file %s: %w", attestPath, err)
		}

		// Verify DSSE Envelope
		var env dsse.Envelope
		if err := json.Unmarshal(attestData, &env); err != nil {
			return fmt.Errorf("attestation file %s is not a valid DSSE envelope: %w", attestPath, err)
		}

		if env.PayloadType != "application/vnd.in-toto+json" && env.PayloadType != "https://in-toto.io/Statement/v1" {
			return fmt.Errorf("attestation file %s has unsupported payloadType: %s. Expected application/vnd.in-toto+json", attestPath, env.PayloadType)
		}

		if len(env.Signatures) == 0 {
			return fmt.Errorf("attestation file %s has no signatures", attestPath)
		}

		// Verify subject digest against the payload unless SkipVerification is true
		if !ao.SkipVerification {
			var stmt IntotoStatement
			if err := json.Unmarshal(env.Payload, &stmt); err != nil {
				return fmt.Errorf("failed to unmarshal payload as in-toto statement: %w", err)
			}

			matched := false
			for _, subj := range stmt.Subject {
				for _, digestVal := range subj.Digest {
					if digestVal == subjectDigest.Hex {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}

			if !matched {
				return fmt.Errorf("subject digest mismatch: attestation %s does not describe the target artifact %s. Use --skip-verification to bypass this check.", attestPath, subjectDigest.String())
			}
		}

		referrerImage := empty.Image

		layer := &attestationLayer{
			data: attestData,
		}

		referrerImage, err = mutate.AppendLayers(referrerImage, layer)
		if err != nil {
			return fmt.Errorf("failed to append attestation layer: %w", err)
		}

		emptyHash := v1.Hash{}
		desc := v1.Descriptor{
			MediaType: types.MediaType("application/vnd.in-toto+json"),
			Digest:    subjectDigest,
			Size:      0,
		}
		if subjectDigest != emptyHash {
			if withSubject, ok := mutate.Subject(referrerImage, desc).(v1.Image); ok {
				referrerImage = withSubject
			} else {
				return fmt.Errorf("failed to cast subject to image")
			}
		}

		referrerDigest, err := referrerImage.Digest()
		if err != nil {
			return fmt.Errorf("failed to get referrer image digest: %w", err)
		}
		
		referrerRef := ref.Context().Digest(referrerDigest.String())
		
		if err := remote.Write(referrerRef, referrerImage, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)); err != nil {
			return fmt.Errorf("failed to write referrer image to registry: %w", err)
		}

		log.Infof("Successfully attached attestation from %s to %s as %s", attestPath, ref.String(), referrerDigest.String())
	}

	return nil
}

type attestationLayer struct {
	data []byte
}

func (l *attestationLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.data))
	return h, err
}

func (l *attestationLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.data))
	return h, err
}

func (l *attestationLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.data)), nil
}

func (l *attestationLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.data)), nil
}

func (l *attestationLayer) Size() (int64, error) {
	return int64(len(l.data)), nil
}

func (l *attestationLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.in-toto+json", nil
}
