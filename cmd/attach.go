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
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

// Media type for witness attestations
const (
	MediaTypeWitnessAttestation = "application/vnd.in-toto.witness.attestation.v1+json"
)

// Subject represents a single subject in an attestation
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement represents the basic structure of an in-toto statement
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     any       `json:"predicate"`
}

// AttachCmd returns a new cobra command for attaching attestations to OCI artifacts
func AttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "attach",
		Short:         "Attaches artifacts to OCI images",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	attestationCmd := &cobra.Command{
		Use:           "attestation <image reference>",
		Short:         "Attaches attestations to an OCI artifact",
		Long:          "Attaches attestations to an OCI artifact (e.g., container image) as additional layers",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("exactly one image reference is required")
			}

			o := options.AttachOptions{}
			o.AddFlags(cmd)

			return runAttachAttestation(cmd.Context(), o, args[0])
		},
	}

	o := options.AttachOptions{}
	o.AddFlags(attestationCmd)

	cmd.AddCommand(attestationCmd)
	return cmd
}

// loadImage loads an image from the specified source
func loadImage(_ context.Context, ao options.AttachOptions, imageRef string) (v1.Image, error) {
	switch ao.Source {

	case options.ImageSourceDocker:
		// Load the image from the Docker daemon
		ref, err := name.ParseReference(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image reference: %w", err)
		}
		return daemon.Image(ref)

	case options.ImageSourceTarball:
		// Load the image from a tarball
		if ao.TarballPath == "" {
			return nil, fmt.Errorf("tarball path must be specified when source is 'tarball'")
		}
		// Use imageRef as the tag for the image in the tarball
		tag, err := name.NewTag(imageRef)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tag: %w", err)
		}
		return tarball.ImageFromPath(ao.TarballPath, &tag)

	default:
		return nil, fmt.Errorf("unsupported image source: %s", ao.Source)
	}
}

// verifyAttestationForImage checks if the attestation matches the image by examining
// the subject digests in the attestation against the image digest
func verifyAttestationForImage(attestationBytes []byte, img v1.Image, attestationPath string) error {
	// Unmarshal the attestation envelope
	var envelope dsse.Envelope
	if err := json.Unmarshal(attestationBytes, &envelope); err != nil {
		return fmt.Errorf("failed to parse attestation as DSSE envelope: %w", err)
	}

	// Unmarshal the payload
	var statement Statement
	if err := json.Unmarshal([]byte(envelope.Payload), &statement); err != nil {
		return fmt.Errorf("failed to parse statement payload: %w", err)
	}

	// Check if we have subjects in the statement
	if len(statement.Subject) == 0 {
		return fmt.Errorf("attestation has no subjects")
	}

	// Get the image digest
	imgDigest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("failed to get image digest: %w", err)
	}
	imgDigestStr := imgDigest.String()

	// Strip the "sha256:" prefix if present
	imgDigestStr = strings.TrimPrefix(imgDigestStr, "sha256:")

	// Calculate container image digests using algorithms mentioned in the attestation
	// For each subject, check if the digest matches any digest of the image
	foundMatch := false
	for _, subject := range statement.Subject {
		for algo, digestValue := range subject.Digest {
			// Handle case where the digest value includes the algorithm prefix
			if strings.HasPrefix(digestValue, algo+":") {
				digestValue = digestValue[len(algo)+1:]
			}

			// Direct comparison with image digest
			if algo == "sha256" && digestValue == imgDigestStr {
				foundMatch = true
				log.Debugf("Found matching digest: %s", digestValue)
				break
			}
		}
		if foundMatch {
			break
		}
	}

	if !foundMatch {
		// For debugging, print the expected and actual digests
		log.Debugf("Image digest: sha256:%s", imgDigestStr)
		log.Debugf("Attestation subjects: %+v", statement.Subject)
		return fmt.Errorf("attestation from %s does not match image digest", attestationPath)
	}

	return nil
}

// runAttachAttestation implements the logic for attaching attestations to an OCI artifact
func runAttachAttestation(ctx context.Context, ao options.AttachOptions, imageRef string) error {
	if len(ao.AttestationFilePaths) == 0 {
		return fmt.Errorf("at least one attestation file is required")
	}

	// Load the image from the specified source
	log.Infof("Loading image from %s source: %s", ao.Source, imageRef)
	img, err := loadImage(ctx, ao, imageRef)
	if err != nil {
		return fmt.Errorf("failed to load image: %w", err)
	}

	// Get the image digest for verification
	imgDigest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("failed to get image digest: %w", err)
	}
	log.Infof("Image digest: %s", imgDigest.String())

	// Count of attached and skipped attestations
	attachedCount := 0
	skippedCount := 0
	var skippedAttestations []string

	// Load and process each attestation file
	for _, attestationPath := range ao.AttestationFilePaths {
		// Read the attestation file
		log.Infof("Reading attestation from %s", attestationPath)
		attestationBytes, err := os.ReadFile(attestationPath)
		if err != nil {
			return fmt.Errorf("failed to read attestation file %s: %w", attestationPath, err)
		}

		// Validate that the attestation is a valid DSSE envelope
		var envelope dsse.Envelope
		if err := json.Unmarshal(attestationBytes, &envelope); err != nil {
			return fmt.Errorf("failed to parse attestation as DSSE envelope: %w", err)
		}

		// Verify signatures on the attestation
		for _, sig := range envelope.Signatures {
			keyID := sig.KeyID
			log.Debugf("Attestation signed by key ID: %s", keyID)
		}

		// Verify that the attestation matches the image
		err = verifyAttestationForImage(attestationBytes, img, attestationPath)
		if err != nil {
			log.Errorf("Skipping attestation from %s: %v", attestationPath, err)
			skippedCount++
			skippedAttestations = append(skippedAttestations, attestationPath)
			continue
		}

		log.Infof("Verified attestation from %s matches image digest", attestationPath)

		// Create a layer from the attestation bytes
		layer := static.NewLayer(attestationBytes, types.MediaType(MediaTypeWitnessAttestation))

		// Append the layer to the image
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			return fmt.Errorf("failed to append attestation layer to image: %w", err)
		}

		log.Infof("Added attestation from %s as a layer", attestationPath)
		attachedCount++
	}

	if attachedCount == 0 {
		errMsg := fmt.Sprintf("no attestations were attached (%d attestations skipped due to verification failures)", skippedCount)
		if len(skippedAttestations) > 0 {
			errMsg += "\nSkipped attestations:"
			for _, path := range skippedAttestations {
				errMsg += "\n  - " + path
			}
			errMsg += "\nEnsure attestations were created for this specific image and contain matching subject digests."
		}
		return fmt.Errorf("%s", errMsg)
	}

	// Add annotations to the image to indicate the presence of attestations
	img = mutate.Annotations(img, map[string]string{
		"org.in-toto.witness/attestations": "true",
	}).(v1.Image)

	// Update config to include labels about attestations
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get config file: %w", err)
	}

	if cfg.Config.Labels == nil {
		cfg.Config.Labels = make(map[string]string)
	}
	cfg.Config.Labels["org.in-toto.witness/attestations"] = "true"

	img, err = mutate.Config(img, cfg.Config)
	if err != nil {
		return fmt.Errorf("failed to update image config: %w", err)
	}

	// Determine the destination reference
	destRef := imageRef

	// Handle different destinations based on the source
	switch ao.Source {

	case options.ImageSourceDocker:
		// Load the image back into the Docker daemon
		tag, err := name.NewTag(destRef)
		if err != nil {
			return fmt.Errorf("failed to parse destination tag for Docker daemon: %w", err)
		}
		log.Infof("Loading image into Docker daemon as %s", tag.Name())
		if _, err := daemon.Write(tag, img); err != nil {
			return fmt.Errorf("failed to load image into Docker daemon: %w", err)
		}

	case options.ImageSourceTarball:
		// Write the image to a tarball
		destPath := ao.TarballPath
		if strings.HasSuffix(destPath, ".tar") {
			destPath = destPath[:len(destPath)-4] + ".witness.tar"
		} else {
			destPath = destPath + ".witness.tar"
		}
		tag, err := name.NewTag(destRef)
		if err != nil {
			return fmt.Errorf("failed to parse destination tag: %w", err)
		}
		log.Infof("Writing image to tarball at %s with tag %s", destPath, tag.Name())
		if err := tarball.WriteToFile(destPath, tag, img); err != nil {
			return fmt.Errorf("failed to write image to tarball: %w", err)
		}

	default:
		return fmt.Errorf("unsupported image source: %s", ao.Source)
	}

	log.Infof("Successfully attached %d attestation(s) to %s (skipped %d)", attachedCount, imageRef, skippedCount)
	return nil
}
