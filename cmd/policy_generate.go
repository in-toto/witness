// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// generatePolicy generates a new policy file based on provided options
func generatePolicy(cmd *cobra.Command, opts *PolicyGenerateOptions) error {
	log.Info("Generating Witness policy...")

	if len(opts.StepNames) == 0 {
		return fmt.Errorf("at least one step must be specified with --step")
	}

	expiresIn, err := time.ParseDuration(opts.ExpiresIn)
	if err != nil {
		return fmt.Errorf("invalid --expires-in duration '%s': %w", opts.ExpiresIn, err)
	}

	pol := &policy.Policy{
		Expires:              metav1.Time{Time: time.Now().Add(expiresIn)},
		Steps:                make(map[string]policy.Step),
		PublicKeys:           make(map[string]policy.PublicKey),
		Roots:                make(map[string]policy.Root),
		TimestampAuthorities: make(map[string]policy.Root),
	}

	rootCAsByStep, err := parseStepMappedFlags(opts.RootCAs)
	if err != nil {
		return fmt.Errorf("failed to parse --root-ca flags: %w", err)
	}

	publicKeysByStep, err := parseStepMappedFlags(opts.PublicKeys)
	if err != nil {
		return fmt.Errorf("failed to parse --public-key flags: %w", err)
	}

	intermediatesByStep, err := parseStepMappedFlags(opts.Intermediates)
	if err != nil {
		return fmt.Errorf("failed to parse --intermediate flags: %w", err)
	}

	attestationsByStep, err := parseAttestationFlags(opts.AttestationTypes)
	if err != nil {
		return fmt.Errorf("failed to parse --attestation flags: %w", err)
	}

	certCNsByStep, err := parseStepMappedFlags(opts.CertCommonName)
	if err != nil {
		return fmt.Errorf("failed to parse --cert-cn flags: %w", err)
	}

	certDNSByStep, err := parseStepMappedFlags(opts.CertDNSNames)
	if err != nil {
		return fmt.Errorf("failed to parse --cert-dns flags: %w", err)
	}

	certEmailsByStep, err := parseStepMappedFlags(opts.CertEmails)
	if err != nil {
		return fmt.Errorf("failed to parse --cert-email flags: %w", err)
	}

	certOrgsByStep, err := parseStepMappedFlags(opts.CertOrgs)
	if err != nil {
		return fmt.Errorf("failed to parse --cert-org flags: %w", err)
	}

	certURIsByStep, err := parseStepMappedFlags(opts.CertURIs)
	if err != nil {
		return fmt.Errorf("failed to parse --cert-uri flags: %w", err)
	}

	artifactsFromByStep, err := parseStepMappedFlags(opts.ArtifactsFrom)
	if err != nil {
		return fmt.Errorf("failed to parse --artifacts-from flags: %w", err)
	}

	for _, stepName := range opts.StepNames {
		log.Infof("Processing step: %s", stepName)

		step := policy.Step{
			Name:          stepName,
			Attestations:  []policy.Attestation{},
			Functionaries: []policy.Functionary{},
			ArtifactsFrom: []string{},
		}
		alwaysRunAttestors := []string{"material", "command-run", "product"}
		addedAttestorTypes := make(map[string]bool)

		for _, attName := range alwaysRunAttestors {
			attestor, err := attestation.GetAttestor(attName)
			if err != nil {
				log.Warnf("Failed to get always-run attestor '%s': %v", attName, err)
				continue
			}

			attType := attestor.Type()
			attestation := policy.Attestation{
				Type:         attType,
				RegoPolicies: []policy.RegoPolicy{},
			}

			step.Attestations = append(step.Attestations, attestation)
			addedAttestorTypes[attType] = true
		}

		if attestationNames, ok := attestationsByStep[stepName]; ok {
			for _, attName := range attestationNames {

				attestor, err := attestation.GetAttestor(attName)
				if err != nil {
					log.Error(err)
				}

				attType := attestor.Type()

				if addedAttestorTypes[attType] {
					log.Infof("Skipping attestation '%s' (type: %s) - already added as always-run attestor", attName, attType)
					continue
				}

				attestation := policy.Attestation{
					Type:         attType,
					RegoPolicies: []policy.RegoPolicy{},
				}
				step.Attestations = append(step.Attestations, attestation)
				addedAttestorTypes[attType] = true
			}
		}

		// TODO: add rego policies logic

		if pubKeyFiles, ok := publicKeysByStep[stepName]; ok {
			for _, pubKeyFile := range pubKeyFiles {
				keyID, pubKey, err := loadPublicKey(pubKeyFile)
				if err != nil {
					return fmt.Errorf("failed to load public key '%s' for step '%s': %w", pubKeyFile, stepName, err)
				}

				pol.PublicKeys[keyID] = pubKey
				step.Functionaries = append(step.Functionaries, policy.Functionary{
					Type:        "publickey",
					PublicKeyID: keyID,
				})
				log.Debugf("Added public key functionary (keyid: %s) for step '%s'", keyID, stepName)
			}
		}

		if rootCAFiles, ok := rootCAsByStep[stepName]; ok {
			for _, rootCAFile := range rootCAFiles {
				keyID, root, err := loadRootCA(rootCAFile)
				if err != nil {
					return fmt.Errorf("failed to load root CA '%s' for step '%s': %w", rootCAFile, stepName, err)
				}

				if intermediateFiles, ok := intermediatesByStep[stepName]; ok {
					for _, intFile := range intermediateFiles {
						intCert, err := loadIntermediateCert(intFile)
						if err != nil {
							return fmt.Errorf("failed to load intermediate '%s' for step '%s': %w", intFile, stepName, err)
						}
						root.Intermediates = append(root.Intermediates, intCert)
					}
				}

				pol.Roots[keyID] = root
				certConstraint := policy.CertConstraint{
					CommonName:    "*",
					DNSNames:      []string{"*"},
					Emails:        []string{"*"},
					Organizations: []string{"*"},
					URIs:          []string{"*"},
					Roots:         []string{keyID},
				}

				if cns, ok := certCNsByStep[stepName]; ok && len(cns) > 0 {
					certConstraint.CommonName = cns[0]
				}
				if dns, ok := certDNSByStep[stepName]; ok && len(dns) > 0 {
					certConstraint.DNSNames = dns
				}
				if emails, ok := certEmailsByStep[stepName]; ok && len(emails) > 0 {
					certConstraint.Emails = emails
				}
				if orgs, ok := certOrgsByStep[stepName]; ok && len(orgs) > 0 {
					certConstraint.Organizations = orgs
				}
				if uris, ok := certURIsByStep[stepName]; ok && len(uris) > 0 {
					certConstraint.URIs = uris
				}

				step.Functionaries = append(step.Functionaries, policy.Functionary{
					Type:           "root",
					CertConstraint: certConstraint,
				})

				log.Debugf("Added root CA functionary (keyid: %s) for step '%s'", keyID, stepName)
			}
		}

		if artifacts, ok := artifactsFromByStep[stepName]; ok {
			step.ArtifactsFrom = artifacts
			log.Debugf("Step '%s' depends on artifacts from: %v", stepName, artifacts)
		}

		if len(step.Functionaries) == 0 {
			return fmt.Errorf("step '%s' has no functionaries (no --public-key or --root-ca specified)", stepName)
		}

		pol.Steps[stepName] = step
	}

	policyJSON, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy to JSON: %w", err)
	}

	if err := os.WriteFile(opts.OutputFile, policyJSON, 0644); err != nil {
		return fmt.Errorf("failed to write policy to '%s': %w", opts.OutputFile, err)
	}

	log.Infof("Policy successfully generated: %s", opts.OutputFile)
	log.Infof("Policy expires: %s", pol.Expires.Format(time.RFC3339))
	log.Infof("Steps: %d", len(pol.Steps))
	log.Infof("Public keys: %d", len(pol.PublicKeys))
	log.Infof("Root CAs: %d", len(pol.Roots))

	return nil
}

// parseStepMappedFlags parses flags in format "step=value"
func parseStepMappedFlags(flags []string) (map[string][]string, error) {
	result := make(map[string][]string)

	for _, flag := range flags {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format '%s': expected 'step=value'", flag)
		}

		stepName := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if stepName == "" || value == "" {
			return nil, fmt.Errorf("invalid format '%s': step name and value cannot be empty", flag)
		}

		result[stepName] = append(result[stepName], value)
	}

	return result, nil
}

// parseAttestationFlags parses attestation flags in format "step=attestor_name"
// It resolves attestor names to their type URLs using the attestation registry
func parseAttestationFlags(flags []string) (map[string][]string, error) {
	result := make(map[string][]string)

	for _, flag := range flags {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid attestation format '%s': expected 'step=attestor_name'", flag)
		}

		stepName := strings.TrimSpace(parts[0])
		attestorName := strings.TrimSpace(parts[1])

		if stepName == "" || attestorName == "" {
			return nil, fmt.Errorf("invalid attestation format '%s': step name and attestor name cannot be empty", flag)
		}

		_, err := attestation.GetAttestor(attestorName)
		if err != nil {
			return nil, fmt.Errorf("unknown attestor '%s' for step '%s': %w\nRun 'witness attestors list' to see available attestors", attestorName, stepName, err)
		}

		result[stepName] = append(result[stepName], attestorName)
	}

	return result, nil
}

// loadPublicKey loads a public key from file and returns its key ID and policy.PublicKey
func loadPublicKey(filePath string) (string, policy.PublicKey, error) {
	keyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", policy.PublicKey{}, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", policy.PublicKey{}, fmt.Errorf("failed to decode PEM block from public key file")
	}

	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", policy.PublicKey{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	hash := sha256.Sum256(keyBytes)
	keyID := fmt.Sprintf("%x", hash)

	return keyID, policy.PublicKey{
		KeyID: keyID,
		Key:   keyBytes,
	}, nil
}

// loadRootCA loads a root CA certificate and returns its key ID and policy.Root
func loadRootCA(filePath string) (string, policy.Root, error) {
	certBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", policy.Root{}, fmt.Errorf("failed to read root CA file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return "", policy.Root{}, fmt.Errorf("failed to decode PEM block from root CA file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", policy.Root{}, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	if !cert.IsCA {
		return "", policy.Root{}, fmt.Errorf("certificate is not a CA certificate (CA:FALSE)")
	}

	if time.Now().After(cert.NotAfter) {
		return "", policy.Root{}, fmt.Errorf("certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
	}

	hash := sha256.Sum256(certBytes)
	keyID := fmt.Sprintf("%x", hash)

	// encodedCert := []byte(base64.StdEncoding.EncodeToString(certBytes))

	return keyID, policy.Root{
		Certificate:   certBytes,
		Intermediates: [][]byte{},
	}, nil
}

// loadIntermediateCert loads an intermediate certificate and returns it base64 encoded
func loadIntermediateCert(filePath string) ([]byte, error) {
	certBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read intermediate certificate file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from intermediate certificate file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate (CA:FALSE)")
	}

	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
	}
	// encodedCert := []byte(base64.StdEncoding.EncodeToString(certBytes))

	return certBytes, nil
}
