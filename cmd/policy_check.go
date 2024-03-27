package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/policy"
	"github.com/open-policy-agent/opa/ast"
	"github.com/spf13/cobra"
)

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

func ReadPolicy(policyFile string) (*policy.Policy, error) {
	policyBytes, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, err
	}

	// Attempt to unmarshal as a DSSE envelope
	e := dsse.Envelope{}
	if err := json.Unmarshal(policyBytes, &e); err == nil {
		if e.Payload != nil {
			fmt.Printf("DSSE Envelope detected, extracting payload\n")
			policyBytes = e.Payload
		}
	} else {

		fmt.Printf("Not a DSSE Envelope, treating as direct policy JSON\n")
	}

	// Unmarshal into the Policy struct
	p := &policy.Policy{}
	if err := json.Unmarshal(policyBytes, p); err != nil {
		fmt.Printf("Error unmarshalling policy: %v\n", err)
		return nil, err
	}

	return p, nil
}

// CheckPolicy checks the policy file for correctness and expiration
func checkPolicy(cmd *cobra.Command, args []string) error {
	//policy is the first argument
	policyFile := args[0]

	errors := []error{}

	p, err := ReadPolicy(policyFile)
	if err != nil {
		fmt.Printf("Error reading policy: %v\n", err)
		return err
	}

	// Make sure the policy is not expired
	if time.Now().After(p.Expires.Time) {
		errors = append(errors, fmt.Errorf("policy time of expiration '%s' has passed", p.Expires.Time))
	}

	// Check that roots exist for all functionaries
	for _, step := range p.Steps {
		for _, att := range step.Attestations {
			for _, module := range att.RegoPolicies {
				err := validateRegoModule(module.Module)
				if err != nil {
					errors = append(errors, fmt.Errorf("error: module '%s' for step '%s' is not valid: %v", module, step.Name, err))
				}
			}
		}

		for _, functionary := range step.Functionaries {
			for _, fRoot := range functionary.CertConstraint.Roots {

				foundRoot := false
				for k := range p.Roots {
					if fRoot == k {
						foundRoot = true
						break
					}
				}
				if !foundRoot {
					errors = append(errors, fmt.Errorf("error: Functionary '%s' for step '%s' not found in Roots.  Please make sure the root exists in the policy's 'Roots' slice", fRoot, step.Name))
				}
			}
		}
	}

	// Check root certificates
	for k, v := range p.Roots {

		//base64 decode the root certificate to get the pem
		block, _ := pem.Decode([]byte(v.Certificate))
		if block == nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is not a valid PEM block", k))
			continue
		}

		//parse the pem to get the x509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is not a valid x509 certificate: %v", k, err))
			continue
		}

		// Check that the root certificate is not expired
		if time.Now().After(cert.NotAfter) {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is expired", k))
		}

		// Check that the root certificate is a CA
		if !cert.IsCA {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' is not a CA", k))
		}

		// Check that the root certificate has a valid signature
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an invalid signature: %v", k, err))
		}

		// Check that the root certificate has a valid public key
		err = cert.CheckSignatureFrom(cert)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an invalid public key: %v", k, err))
		}

		// check that the expiration date is not before the policy expiration date
		if cert.NotAfter.Before(p.Expires.Time) {
			errors = append(errors, fmt.Errorf("error: root certificate '%s' has an expiration date before the policy expiration date", k))
		}

		//if root has an intermediate, check that intermediate
		if len(v.Intermediates) > 0 {
			for _, intermediate := range v.Intermediates {

				// Check that the intermediate certificate is valid
				block, _ := pem.Decode([]byte(intermediate))
				if block == nil {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is not a valid PEM block", k))
					continue
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is not a valid x509 certificate: %v", k, err))
					continue
				}

				// Check that the intermediate certificate is not expired
				if time.Now().After(cert.NotAfter) {
					errors = append(errors, fmt.Errorf("error: intermediate certificate '%s' is expired", k))
				}
			}
		}
	}

	//check the timestamp authority
	for k, v := range p.TimestampAuthorities {
		// Check that the timestamp authority certificate is valid
		block, _ := pem.Decode([]byte(v.Certificate))
		if block == nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a valid PEM block", k))
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a valid x509 certificate: %v", k, err))
			continue
		}

		// Check that the timestamp authority certificate is not expired
		if cert != nil && time.Now().After(cert.NotAfter) {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is expired", k))
		}

		// Check that the timestamp authority certificate is a CA
		if !cert.IsCA {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' is not a CA", k))
		}

		// Check that the timestamp authority certificate has a valid signature
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid signature: %v", k, err))
		}

		// Check that the timestamp authority certificate has a valid public key
		err = cert.CheckSignatureFrom(cert)
		if err != nil {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an invalid public key: %v", k, err))
		}

		// check that the expiration date is not before the policy expiration date
		if cert.NotAfter.Before(p.Expires.Time) {
			errors = append(errors, fmt.Errorf("error: timestamp authority certificate '%s' has an expiration date before the policy expiration date", k))
		}
	}

	if len(errors) > 0 {
		return NewPolicyCheckError(errors)
	}

	return nil
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
