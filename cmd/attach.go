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
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/types"
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
		Use:               "attestation <image_ref>",
		Short:             "Attach an attestation file as an OCI referrer",
		Long:              "Attach an attestation JSON file as an OCI referrer to a container image in a registry",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Args:              cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttachAttestation(cmd.Context(), ao, args[0])
		},
	}

	ao.AddFlags(cmd)
	return cmd
}

func runAttachAttestation(ctx context.Context, ao options.AttachOptions, imageRef string) error {
	if len(ao.AttestationFilePaths) == 0 {
		return fmt.Errorf("at least one attestation file must be specified with --attestation")
	}

	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Get the original image descriptor from the registry
	originalImage, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		if _, errIndex := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)); errIndex == nil {
			// Actually we might want to attach to an Index as well.
			// Let's just use remote.Head to get the digest instead of remote.Image
			originalDesc, errHead := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
			if errHead != nil {
				return fmt.Errorf("failed to fetch image/index from registry: %w", errHead)
			}
			return attachToSubject(ctx, ao, ref, originalDesc.Digest)
		}
		return fmt.Errorf("failed to fetch image from registry: %w", err)
	}

	originalDigest, err := originalImage.Digest()
	if err != nil {
		return fmt.Errorf("failed to get original image digest: %w", err)
	}

	return attachToSubject(ctx, ao, ref, originalDigest)
}

func attachToSubject(ctx context.Context, ao options.AttachOptions, ref name.Reference, subjectDigest v1.Hash) error {
	for _, attestPath := range ao.AttestationFilePaths {
		attestData, err := os.ReadFile(attestPath)
		if err != nil {
			return fmt.Errorf("failed to read attestation file %s: %w", attestPath, err)
		}

		referrerImage := empty.Image

		layer := &attestationLayer{
			data: attestData,
		}

		referrerImage, err = mutate.AppendLayers(referrerImage, layer)
		if err != nil {
			return fmt.Errorf("failed to append attestation layer: %w", err)
		}

		// A bug in remote.Write will complain about media type unless we explicitly override
		emptyHash := v1.Hash{}
		desc := v1.Descriptor{
			MediaType: types.MediaType("application/vnd.in-toto+json"),
			Digest:    subjectDigest,
			Size:      0, // the actual digest size doesn't matter for the subject descriptor
		}
		if subjectDigest != emptyHash {
			if withSubject, ok := mutate.Subject(referrerImage, desc).(v1.Image); ok {
				referrerImage = withSubject
			} else {
				return fmt.Errorf("failed to cast subject to image")
			}
		}

		// We need to write this to the registry. The registry needs a reference to write to.
		// Usually we push to a digest reference of the referrer itself or a tag. 
		// If we use remote.Write with the digest, it will push it.
		// Wait, ref is the repository. We can get the digest of the referrerImage
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
