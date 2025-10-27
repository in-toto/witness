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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/spf13/cobra"
)

type ValidationResult struct {
	Valid            bool              `json:"valid"`
	Errors           []ValidationError `json:"errors,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	ChecksPerformed  int               `json:"checks_performed"`
	ChecksPassed     int               `json:"checks_passed"`
	PolicyFile       string            `json:"policy_file"`
	PolicyExpiration string            `json:"policy_expiration,omitempty"`
}

type ValidationError struct {
	Category   string `json:"category"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
	Location   string `json:"location,omitempty"`
}

type PolicyCheckError struct {
	Errors []error
}

func (e *PolicyCheckError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "\n")
}

func NewPolicyCheckError(errors []error) error {
	if len(errors) == 0 {
		return nil
	}
	return &PolicyCheckError{Errors: errors}
}

func ReadPolicy(policyFile string, verbose bool) (*policy.Policy, bool, error) {
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read policy file: %w", err)
	}

	isDSSE := false
	// Attempt to unmarshal as a DSSE envelope
	e := dsse.Envelope{}
	if err := json.Unmarshal(policyBytes, &e); err == nil {
		if e.Payload != nil {
			if verbose {
				log.Info("DSSE Envelope detected, extracting payload")
			}
			policyBytes = e.Payload
			isDSSE = true
		}
	} else {
		if verbose {
			log.Info("Direct policy JSON detected")
		}
	}

	// Unmarshal into the Policy struct
	p := &policy.Policy{}
	if err := json.Unmarshal(policyBytes, p); err != nil {
		return nil, isDSSE, fmt.Errorf("failed to parse policy JSON: %w\nHint: Ensure the policy is valid JSON and follows the witness policy schema", err)
	}

	return p, isDSSE, nil
}

// CheckPolicy checks the policy file for correctness and expiration
func checkPolicy(cmd *cobra.Command, args []string) error {
	policyFile := args[0]

	verbose, _ := cmd.Flags().GetBool("verbose")
	quiet, _ := cmd.Flags().GetBool("quiet")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	result := &ValidationResult{
		Valid:           true,
		PolicyFile:      policyFile,
		ChecksPerformed: 0,
		ChecksPassed:    0,
	}

	if verbose && !jsonOutput {
		log.Infof("Validating policy: %s", policyFile)
	}

	// Read and parse policy
	if verbose && !jsonOutput {
		log.Infof("Reading policy file...")
	}
	p, isDSSE, err := ReadPolicy(policyFile, verbose && !jsonOutput)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Category:   "Policy File",
			Message:    err.Error(),
			Suggestion: "Check that the file exists and contains valid JSON",
		})
		return outputResult(result, jsonOutput, quiet)
	}
	result.ChecksPerformed++
	result.ChecksPassed++
	result.PolicyExpiration = p.Expires.Format(time.RFC3339)

	if verbose && !jsonOutput {
		if isDSSE {
			log.Info("DSSE envelope format")
		}
		log.Info("Valid JSON structure")
		log.Infof("Policy expires: %s", p.Expires.Format(time.RFC3339))
	}

	// Check policy expiration
	if verbose && !jsonOutput {
		log.Info("Checking policy expiration...")
	}
	result.ChecksPerformed++
	if time.Now().After(p.Expires.Time) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Category:   "Policy Expiration",
			Message:    fmt.Sprintf("Policy expired on %s", p.Expires.Format(time.RFC3339)),
			Suggestion: "Update the 'expires' field to a future date",
			Location:   "expires",
		})
	} else {
		result.ChecksPassed++
		if verbose && !jsonOutput {
			daysUntilExpiry := int(time.Until(p.Expires.Time).Hours() / 24)
			log.Infof("Policy valid until %s (%d days)", p.Expires.Format("2006-01-02"), daysUntilExpiry)

			// Warning for soon-to-expire policies
			if daysUntilExpiry < 30 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Policy expires in %d days", daysUntilExpiry))
				log.Warnf("Warning: Policy expires in %d days", daysUntilExpiry)
			}
		}
	}

	// Validate Rego policies
	if verbose && !jsonOutput {
		log.Info("Validating Rego policies...")
	}
	regoCount := 0
	for stepName, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, module := range att.RegoPolicies {
				regoCount++
				result.ChecksPerformed++

				if verbose && !jsonOutput {
					log.Infof("Checking module '%s' in step '%s'...", module.Name, stepName)
				}

				err := validateRegoModule(module.Module)
				if err != nil {
					result.Valid = false

					// Try to show the actual Rego code
					regoCode := ""
					if decoded, decErr := base64.StdEncoding.DecodeString(string(module.Module)); decErr == nil {
						regoCode = string(decoded)
					}

					errMsg := fmt.Sprintf("Rego module '%s' in step '%s' is invalid: %v", module.Name, stepName, err)
					suggestion := "Check Rego syntax. Common issues:\n" +
						"  - Missing 'package' declaration\n" +
						"  - Syntax errors in deny rules\n" +
						"  - Invalid comparison operators"

					if regoCode != "" {
						suggestion += fmt.Sprintf("\n\nRego code:\n%s", regoCode)
					}

					result.Errors = append(result.Errors, ValidationError{
						Category:   "Rego Policy",
						Message:    errMsg,
						Suggestion: suggestion,
						Location:   fmt.Sprintf("steps.%s.attestations[].regopolicies", stepName),
					})
				} else {
					result.ChecksPassed++
					if verbose && !jsonOutput {
						log.Infof("Module '%s' is valid", module.Name)
					}
				}
			}
		}
	}

	if verbose && !jsonOutput {
		log.Infof("Validated %d Rego module(s)", regoCount)
	}

	// Validate functionary root references
	if verbose && !jsonOutput {
		log.Info("Validating functionaries...")
	}

	funcCount := 0
	for stepName, step := range p.Steps {
		for _, functionary := range step.Functionaries {
			if functionary.CertConstraint.Roots != nil {
				for _, fRoot := range functionary.CertConstraint.Roots {
					funcCount++
					result.ChecksPerformed++

					foundRoot := false
					for k := range p.Roots {
						if fRoot == k {
							foundRoot = true
							break
						}
					}

					if !foundRoot {
						result.Valid = false
						availableRoots := []string{}
						for k := range p.Roots {
							availableRoots = append(availableRoots, k)
						}

						result.Errors = append(result.Errors, ValidationError{
							Category:   "Functionary",
							Message:    fmt.Sprintf("Functionary references root '%s' in step '%s' but it doesn't exist", fRoot, stepName),
							Suggestion: fmt.Sprintf("Add root '%s' to the policy's 'roots' section or use one of: %v", fRoot, availableRoots),
							Location:   fmt.Sprintf("steps.%s.functionaries[].certconstraint.roots", stepName),
						})
					} else {
						result.ChecksPassed++
						if verbose && !jsonOutput {
							log.Infof("Root '%s' exists for step '%s'", fRoot, stepName)
						}
					}
				}
			}
		}
	}
	if verbose && !jsonOutput {
		log.Infof("Validated %d functionary root reference(s)", funcCount)
	}

	// Validate root certificates
	if verbose && !jsonOutput {
		log.Info("Validating root certificates...")
	}
	for k, v := range p.Roots {
		if verbose && !jsonOutput {
			log.Infof("Checking root certificate '%s'...", k)
		}

		// PEM decode
		result.ChecksPerformed++
		block, _ := pem.Decode(v.Certificate)
		if block == nil {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' is not a valid PEM block", k),
				Suggestion: "Ensure the certificate field contains a base64-encoded PEM certificate.\nExample: cat cert.pem | base64 | tr -d '\\n'",
				Location:   fmt.Sprintf("roots.%s.certificate", k),
			})
			continue
		}
		result.ChecksPassed++

		// x509 parse
		result.ChecksPerformed++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' is not a valid x509 certificate: %v", k, err),
				Suggestion: "Regenerate the certificate or check that it's not corrupted",
				Location:   fmt.Sprintf("roots.%s.certificate", k),
			})
			continue
		}
		result.ChecksPassed++
		if verbose && !jsonOutput {
			log.Infof("Valid x509 certificate (CN=%s)", cert.Subject.CommonName)
		}

		// Check CA status
		result.ChecksPerformed++
		if !cert.IsCA {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' is not a CA certificate", k),
				Suggestion: "Root certificates must have CA:TRUE in the Basic Constraints extension.\nRegenerate with: openssl req ... -extensions v3_ca",
				Location:   fmt.Sprintf("roots.%s", k),
			})
		} else {
			result.ChecksPassed++
		}

		// Check expiration
		result.ChecksPerformed++
		if time.Now().After(cert.NotAfter) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' expired on %s", k, cert.NotAfter.Format(time.RFC3339)),
				Suggestion: "Replace with a valid certificate or regenerate",
				Location:   fmt.Sprintf("roots.%s", k),
			})
		} else {
			result.ChecksPassed++
		}

		// Check signatures
		result.ChecksPerformed += 2
		sigErr := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		selfSigErr := cert.CheckSignatureFrom(cert)
		if sigErr != nil || selfSigErr != nil {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' has invalid signature", k),
				Suggestion: "The certificate may be corrupted. Regenerate or re-export the certificate",
				Location:   fmt.Sprintf("roots.%s", k),
			})
		} else {
			result.ChecksPassed += 2
		}

		// Check cert expiration vs policy expiration
		result.ChecksPerformed++
		if cert.NotAfter.Before(p.Expires.Time) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Category:   "Root Certificate",
				Message:    fmt.Sprintf("Root certificate '%s' expires before the policy", k),
				Suggestion: "The certificate must be valid for at least as long as the policy",
				Location:   fmt.Sprintf("roots.%s", k),
			})
		} else {
			result.ChecksPassed++
		}

		if verbose && !jsonOutput {
			log.Infof("Root certificate '%s' is valid", k)
		}
	}
	if verbose && !jsonOutput {
		log.Infof("Validated %d root certificate(s)", len(p.Roots))
	}

	// Validate timestamp authorities (if any)
	if len(p.TimestampAuthorities) > 0 {
		if verbose && !jsonOutput {
			log.Info("Validating timestamp authorities...")
		}
		for k, v := range p.TimestampAuthorities {
			result.ChecksPerformed++
			block, _ := pem.Decode(v.Certificate)
			if block == nil {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Category:   "Timestamp Authority",
					Message:    fmt.Sprintf("Timestamp authority certificate '%s' is not a valid PEM block", k),
					Suggestion: "Ensure the certificate is base64-encoded PEM format",
					Location:   fmt.Sprintf("timestampauthorities.%s.certificate", k),
				})
				continue
			}
			result.ChecksPassed++

			result.ChecksPerformed++
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Category:   "Timestamp Authority",
					Message:    fmt.Sprintf("Timestamp authority certificate '%s' is not valid: %v", k, err),
					Suggestion: "Check the certificate encoding and validity",
					Location:   fmt.Sprintf("timestampauthorities.%s", k),
				})
				continue
			}
			result.ChecksPassed++

			// Validate expiration, CA status, etc.
			result.ChecksPerformed += 2
			if cert != nil && time.Now().After(cert.NotAfter) {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Category:   "Timestamp Authority",
					Message:    fmt.Sprintf("Timestamp authority certificate '%s' expired", k),
					Suggestion: "Replace with a valid certificate",
					Location:   fmt.Sprintf("timestampauthorities.%s", k),
				})
			} else {
				result.ChecksPassed++
			}

			if !cert.IsCA {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Category:   "Timestamp Authority",
					Message:    fmt.Sprintf("Timestamp authority certificate '%s' is not a CA", k),
					Suggestion: "Timestamp authority certificates must be CA certificates",
					Location:   fmt.Sprintf("timestampauthorities.%s", k),
				})
			} else {
				result.ChecksPassed++
			}

			if verbose && !jsonOutput {
				log.Infof("Timestamp authority '%s' is valid", k)
			}
		}
	}

	return outputResult(result, jsonOutput, quiet)
}

func outputResult(result *ValidationResult, jsonOutput bool, quiet bool) error {
	if jsonOutput {
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
		if !result.Valid {
			return fmt.Errorf("policy validation failed")
		}
		return nil
	}

	if result.Valid {
		if !quiet {
			log.Infof("Policy validation successful!")
			log.Info("Summary:")
			log.Infof("Total checks: %d", result.ChecksPerformed)
			log.Infof("Passed: %d", result.ChecksPassed)
			log.Infof("Failed: %d", len(result.Errors))
			if len(result.Warnings) > 0 {
				log.Warnf("Warnings: %d", len(result.Warnings))
			}
		}
		return nil
	}

	// Print errors
	log.Errorf("Policy validation failed")

	// Group errors by category
	errorsByCategory := make(map[string][]ValidationError)
	for _, err := range result.Errors {
		errorsByCategory[err.Category] = append(errorsByCategory[err.Category], err)
	}

	for category, errors := range errorsByCategory {
		log.Infof("%s (%d error%s):", category, len(errors), pluralize(len(errors)))
		for i, err := range errors {
			log.Infof("%d. %s", i+1, err.Message)
			if err.Location != "" {
				log.Infof("Location: %s", err.Location)
			}
			if err.Suggestion != "" {
				log.Infof("Suggestion: %s", err.Suggestion)
			}
		}
	}

	log.Info("Summary:")
	log.Infof("Total checks: %d", result.ChecksPerformed)
	log.Infof("Passed: %d", result.ChecksPassed)
	log.Infof("Failed: %d", len(result.Errors))
	if len(result.Warnings) > 0 {
		log.Warnf("Warnings: %d", len(result.Warnings))
	}

	return fmt.Errorf("policy validation failed with %d error(s)", len(result.Errors))
}

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func validateRegoModule(module []byte) error {
	parsed, err := ast.ParseModule("my_module.rego", string(module))
	if err != nil {
		return fmt.Errorf("failed to parse Rego module: %v", err)
	}
	compiler := ast.NewCompiler()
	if compiler.Compile(map[string]*ast.Module{"my_module": parsed}); compiler.Failed() {
		return errors.New("failed to compile Rego module")
	}
	return nil
}
