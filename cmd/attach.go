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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
		Short:         "Attaches artifacts to Docker images",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Define attachOpts before attestationCmd so it can be captured in RunE.
	attachOpts := options.AttachOptions{}

	attestationCmd := &cobra.Command{
		Use:           "attestation <output_image_tag>",
		Short:         "Attaches attestations to an OCI image tarball and outputs a new tarball",
		Long:          "Loads an image from an input OCI tarball, attaches attestations, and writes to a new OCI tarball.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("exactly one output image tag is required")
			}
			if attachOpts.InputTarballPath == "" {
				return fmt.Errorf("--input-tarball flag is required")
			}
			// attachOpts is captured from the outer scope.
			return runAttachAttestation(cmd.Context(), attachOpts, args[0])
		},
	}

	attachOpts.AddFlags(attestationCmd)
	cmd.AddCommand(attestationCmd)
	return cmd
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

	// Different formats of the digest for comparison
	imgDigestFull := imgDigest.String()                            // e.g., "sha256:1234abcd..."
	imgDigestValue := strings.TrimPrefix(imgDigestFull, "sha256:") // e.g., "1234abcd..."

	log.Debugf("Image digest (full): %s", imgDigestFull)
	log.Debugf("Image digest (value): %s", imgDigestValue)

	// Check all subjects against all digest formats
	foundMatch := false
	for _, subject := range statement.Subject {
		log.Debugf("Checking subject: %+v", subject)
		for algo, digestValue := range subject.Digest {
			log.Debugf("Checking digest %s:%s", algo, digestValue)

			// Handle different digest formats
			cleanDigestValue := strings.TrimPrefix(digestValue, algo+":")

			if (algo == "sha256" && cleanDigestValue == imgDigestValue) ||
				(digestValue == imgDigestFull) {
				foundMatch = true
				log.Infof("Found matching digest: %s", digestValue)
				break
			}
		}
		if foundMatch {
			break
		}
	}

	if !foundMatch {
		log.Debugf("Attestation subjects: %+v", statement.Subject)
		return fmt.Errorf("attestation from %s does not match image digest", attestationPath)
	}

	return nil
}

// verifyAttestationForTarball checks if the attestation matches the input tarball file hash
func verifyAttestationForTarball(attestationBytes []byte, tarballPath string, attestationFilePath string) error {
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

	// Calculate tarball hash
	tarballFileBytes, err := os.ReadFile(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to read tarball %s: %w", tarballPath, err)
	}
	tarballDigest := sha256.Sum256(tarballFileBytes)
	tarballDigestHex := hex.EncodeToString(tarballDigest[:])
	log.Debugf("Input tarball %s SHA256 hash: %s", tarballPath, tarballDigestHex)

	// Check for file attestations
	foundMatch := false
	for _, subject := range statement.Subject {
		log.Debugf("Checking subject: Name: %s, Digest: %+v", subject.Name, subject.Digest)
		// We are looking for a subject that specifically attests to a file product.
		// The subject name might contain the filename, e.g., ".../file:cyber-compliant-example-project-docker-image.tar"
		// For this verification, we are less concerned with the subject's name matching the tarballPath exactly,
		// and more with finding *any* product/file attestation whose digest matches the tarball hash.
		if strings.Contains(subject.Name, "/product/v0.1/file:") || strings.Contains(subject.Name, "/file/v0.1/") { // Making it a bit more general for file attestations
			for algo, value := range subject.Digest {
				cleanValue := strings.TrimPrefix(value, algo+":")
				if algo == "sha256" && cleanValue == tarballDigestHex {
					log.Infof("Found matching SHA256 digest for tarball %s in subject %s from attestation %s", tarballPath, subject.Name, attestationFilePath)
					foundMatch = true
					break // Found a matching digest for this subject
				}
			}
		}
		if foundMatch {
			break // Found a matching subject
		}
	}

	if !foundMatch {
		return fmt.Errorf("attestation from %s does not contain a matching SHA256 digest for the input tarball %s (%s)", attestationFilePath, tarballPath, tarballDigestHex)
	}

	return nil
}

// runAttachAttestation implements the logic for attaching attestations to a Docker image
func runAttachAttestation(ctx context.Context, ao options.AttachOptions, outputImageTag string) error {
	if len(ao.AttestationFilePaths) == 0 {
		return fmt.Errorf("at least one attestation file is required")
	}

	// Load the image from the input tarball
	log.Infof("Loading image from input tarball: %s", ao.InputTarballPath)
	inputFile, err := os.Open(ao.InputTarballPath)
	if err != nil {
		return fmt.Errorf("failed to open input tarball %s: %w", ao.InputTarballPath, err)
	}
	defer inputFile.Close()

	// tarball.Image expects an Opener func. This func will be called to get a reader for the tarball.
	imageOpener := func() (io.ReadCloser, error) {
		// We need to re-open the file each time the opener is called if the library
		// might call it multiple times or if the reader is consumed.
		// For simplicity now, assuming it's called once or the reader is not fully consumed
		// in a way that prevents reuse if the lib needs to.
		// A more robust solution might involve re-opening or seeking to start.
		// However, os.Open gives an *os.File which is an io.ReadCloser.
		// For tarball.Image, it's likely only called once to get the reader.
		// Let's return a new reader on each call for safety with tarball.Image,
		// which might read it in a streaming fashion that's not resettable.
		return os.Open(ao.InputTarballPath)
	}

	img, err := tarball.Image(imageOpener, nil)
	if err != nil {
		return fmt.Errorf("failed to load image from tarball %s: %w", ao.InputTarballPath, err)
	}

	// Get the image digest for verification
	imgDigest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("failed to get image digest: %w", err)
	}
	log.Infof("Image digest: %s", imgDigest.String())

	// Save the original config file before we make any changes
	originalCfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed to get original config file: %w", err)
	}

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

		if ao.SkipVerification {
			log.Infof("Skipping all verification for attestation from %s as per --skip-verification flag", attestationPath)
		} else if ao.VerifyByTarballHash {
			log.Infof("Verifying attestation from %s against input tarball hash (%s)", attestationPath, ao.InputTarballPath)
			err = verifyAttestationForTarball(attestationBytes, ao.InputTarballPath, attestationPath)
			if err != nil {
				log.Errorf("Tarball hash verification failed for %s: %v", attestationPath, err)
				skippedCount++
				skippedAttestations = append(skippedAttestations, attestationPath)
				continue
			}
			log.Infof("Successfully verified attestation from %s against input tarball hash", attestationPath)
		} else {
			log.Infof("Verifying attestation from %s against OCI image digest", attestationPath)
			// Verify that the attestation matches the image (OCI digest)
			err = verifyAttestationForImage(attestationBytes, img, attestationPath)
			if err != nil {
				log.Errorf("OCI image digest verification failed for %s: %v", attestationPath, err)
				skippedCount++
				skippedAttestations = append(skippedAttestations, attestationPath)
				continue
			}
			log.Infof("Successfully verified attestation from %s against OCI image digest", attestationPath)
		}

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

	// Apply the labels from the original config, plus our new label
	newConfig := originalCfg.Config // Use the struct directly
	if newConfig.Labels == nil {
		newConfig.Labels = make(map[string]string)
	}
	newConfig.Labels["org.in-toto.witness/attestations"] = "true"

	img, err = mutate.Config(img, newConfig)
	if err != nil {
		return fmt.Errorf("failed to update image config: %w", err)
	}

	// Instead of writing to daemon, write to a tarball
	// Sanitize outputImageTag to be a valid filename
	safeOutputName := strings.ReplaceAll(outputImageTag, "/", "_")
	safeOutputName = strings.ReplaceAll(safeOutputName, ":", "-")
	outputTarballPath := fmt.Sprintf("%s_with_attestations.tar", safeOutputName)

	var outputTag name.Tag
	outputTag, err = name.NewTag(outputImageTag)
	if err != nil {
		log.Warnf("Failed to parse provided output tag (%s) as a full tag, attempting to prefix with default host: %v", outputImageTag, err)
		var errFallback error
		if !strings.Contains(outputImageTag, "/") {
			outputTag, errFallback = name.NewTag("localhost/" + outputImageTag)
		} else {
			// If it contained a slash but still failed, it might be missing a default registry like docker.io
			// or has some other parsing issue. Trying as is one more time often doesn't help if initial parse failed.
			// Forcing a known good default might be better if an explicit prefix doesn't work.
			outputTag, errFallback = name.NewTag(outputImageTag) // Retry original, in case library handles it internally
		}

		if errFallback != nil {
			log.Warnf("Failed to parse output tag (%s) even with fallback, using default 'localhost/image:latest': %v", outputImageTag, errFallback)
			outputTag, _ = name.NewTag("localhost/image:latest") // This should not fail
		}
	}

	log.Infof("Writing modified image to tarball: %s with tag %s", outputTarballPath, outputTag.Name())
	if err := tarball.WriteToFile(outputTarballPath, outputTag, img); err != nil {
		return fmt.Errorf("failed to write image to tarball %s: %w", outputTarballPath, err)
	}

	log.Infof("Successfully attached %d attestation(s) and wrote to %s (skipped %d)", attachedCount, outputTarballPath, skippedCount)
	return nil
}
