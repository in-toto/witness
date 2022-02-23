// Copyright 2022 The Witness Contributors
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

package policy

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

type checkConstraintAttributeCase struct {
	Constraints []string
	Values      []string
	Expected    bool
}

func TestCheckCertConstraint(t *testing.T) {
	cases := []checkConstraintAttributeCase{
		{
			Constraints: []string{"test1", "test2"},
			Values:      []string{"test2", "test1"},
			Expected:    true,
		},
		{
			Constraints: []string{"test1", "test2"},
			Values:      []string{"test2"},
			Expected:    false,
		},
		{
			Constraints: []string{AllowAllConstraint},
			Values:      []string{"any", "thing", "goes"},
			Expected:    true,
		},
		{
			Constraints: []string{},
			Values:      []string{},
			Expected:    true,
		},
		{
			Constraints: []string{},
			Values:      []string{"test1"},
			Expected:    false,
		},
		{
			Constraints: []string{""},
			Values:      []string{""},
			Expected:    true,
		},
		{
			Constraints: []string{""},
			Values:      []string{"test1"},
			Expected:    false,
		},
		{
			Constraints: []string{"test1", "test2"},
			Values:      []string{"test1", "test2", "test3"},
			Expected:    false,
		},
	}

	for _, c := range cases {
		err := checkCertConstraint("constraint", c.Constraints, c.Values)
		assert.Equal(t, c.Expected, err == nil, fmt.Sprintf("Constraints: %v, Values: %v", c.Constraints, c.Values))
	}
}

type constraintCheckCase struct {
	Constraint CertConstraint
	Cert       *x509.Certificate
	Expected   bool
}

func TestConstraintCheck(t *testing.T) {
	testCertSubject := pkix.Name{
		CommonName:   "step1.example.com",
		Organization: []string{"example"},
	}
	testCertEmails := []string{"example@example.com"}
	testCertDNSNames := []string{"example.com"}
	testCertURI, _ := url.Parse("spiffe://example.com/step1")
	testCertURIs := []*url.URL{testCertURI}
	testertValidity := 1 * time.Hour
	testCertPublicKeyAlgorithm := x509.Ed25519
	testCertTemplate := &x509.Certificate{
		Subject:        testCertSubject,
		EmailAddresses: testCertEmails,
		DNSNames:       testCertDNSNames,
		URIs:           testCertURIs,
	}

	testCert, testIntermediateCert, testRootCert, err := createTestCert(testCertTemplate, testCertPublicKeyAlgorithm, testertValidity)
	require.NoError(t, err)
	verifier, err := cryptoutil.NewX509Verifier(testCert, []*x509.Certificate{testIntermediateCert}, []*x509.Certificate{testRootCert}, time.Time{})
	require.NoError(t, err)
	trustBundles := map[string]TrustBundle{
		"example": {
			Root:          testRootCert,
			Intermediates: []*x509.Certificate{testIntermediateCert},
		},
	}

	cases := []constraintCheckCase{
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{"example.com"},
				Emails:        []string{"example@example.com"},
				Organizations: []string{"example"},
				Roots:         []string{"example"},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: true,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "*",
				DNSNames:      []string{"*"},
				Emails:        []string{"*"},
				Organizations: []string{"*"},
				Roots:         []string{"*"},
				URIs:          []string{"*"},
			},
			Expected: true,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "",
				DNSNames:      []string{},
				Emails:        []string{},
				Organizations: []string{},
				Roots:         []string{},
				URIs:          []string{},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "",
				DNSNames:      []string{""},
				Emails:        []string{""},
				Organizations: []string{""},
				Roots:         []string{""},
				URIs:          []string{""},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "",
				DNSNames:      []string{"example.com"},
				Emails:        []string{"example@example.com"},
				Organizations: []string{"example"},
				Roots:         []string{"example"},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{},
				Emails:        []string{"example@example.com"},
				Organizations: []string{"example"},
				Roots:         []string{"example"},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{"example.com"},
				Emails:        []string{},
				Organizations: []string{"example"},
				Roots:         []string{"example"},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{"example.com"},
				Emails:        []string{"example@example.com"},
				Organizations: []string{},
				Roots:         []string{"example"},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{"example.com"},
				Emails:        []string{"example@example.com"},
				Organizations: []string{"example"},
				Roots:         []string{},
				URIs:          []string{"spiffe://example.com/step1"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "*",
				DNSNames:      []string{"*"},
				Emails:        []string{"*"},
				Organizations: []string{"*"},
				Roots:         []string{"example2"},
				URIs:          []string{"*"},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "step1.example.com",
				DNSNames:      []string{"example.com"},
				Emails:        []string{"example@example.com"},
				Organizations: []string{"example"},
				Roots:         []string{"example"},
				URIs:          []string{},
			},
			Expected: false,
		},
		{
			Cert: testCert,
			Constraint: CertConstraint{
				CommonName:    "*",
				DNSNames:      []string{"*"},
				Emails:        []string{"*"},
				Organizations: []string{"*"},
				Roots:         []string{"*"},
				URIs:          []string{"spiffe://example.com/step2"},
			},
			Expected: false,
		},
	}

	for _, c := range cases {
		err := c.Constraint.Check(verifier, trustBundles)
		assert.Equal(t, c.Expected, err == nil, fmt.Sprintf("Constraint: %v, Errors: %s", c.Constraint, err))
	}
}

func createTestCert(template *x509.Certificate, publicKeyAlgorithm x509.PublicKeyAlgorithm, validity time.Duration) (*x509.Certificate, *x509.Certificate, *x509.Certificate, error) {
	rootCertSubject := pkix.Name{
		CommonName: "Root CA",
	}
	rootCertMaxPathLen := 1
	rootCertValidity := 10 * 365 * 24 * time.Hour // 10 years
	rootCertPublicKeyAlgorithm := x509.Ed25519
	rootCertTemplate := &x509.Certificate{
		Subject:    rootCertSubject,
		MaxPathLen: rootCertMaxPathLen,
	}
	rootCert, _, rootKey, err := createSelfSignedCA(rootCertTemplate, rootCertPublicKeyAlgorithm, rootCertValidity)
	if err != nil {
		return nil, nil, nil, err
	}

	intermediateCertSubject := pkix.Name{
		CommonName: "Intermediate CA",
	}
	intermediateCertMaxPathLen := 0
	intermediateCertValidity := 10 * 365 * 24 * time.Hour
	intermediateCertPublicKeyAlgorithm := x509.Ed25519
	intermediateCertTemplate := &x509.Certificate{
		Subject:    intermediateCertSubject,
		MaxPathLen: intermediateCertMaxPathLen,
	}
	intermediateCert, _, intermediateKey, err := createCA(intermediateCertTemplate, rootCert, rootKey, intermediateCertPublicKeyAlgorithm, intermediateCertValidity)
	if err != nil {
		return nil, nil, nil, err
	}

	endEntityCert, _, _, err := createEndEntityCert(template, intermediateCert, intermediateKey, publicKeyAlgorithm, validity)
	if err != nil {
		return nil, nil, nil, err
	}

	return endEntityCert, intermediateCert, rootCert, nil
}

func createSelfSignedCA(template *x509.Certificate, publicKeyAlgorithm x509.PublicKeyAlgorithm, validity time.Duration) (*x509.Certificate, []byte, crypto.PrivateKey, error) {
	if template.Subject.CommonName == "" {
		return nil, nil, nil, fmt.Errorf("subject common name must be set")
	}

	if template.MaxPathLen <= 0 {
		return nil, nil, nil, fmt.Errorf("maxPathLen must be set and greater than 0")
	}

	serialNumber, err := createSerialNumber()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate serial number: %w", err)
	}

	template.SerialNumber = serialNumber
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(validity)
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.MaxPathLenZero = false

	publicKey, privateKey, err := createKeyPair(publicKeyAlgorithm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	cert, certPEM, err := createCert(template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	return cert, certPEM, privateKey, nil
}

func createCA(template, issuerCert *x509.Certificate, issuerPrivateKey crypto.PrivateKey, publicKeyAlgorithm x509.PublicKeyAlgorithm, validity time.Duration) (*x509.Certificate, []byte, crypto.PrivateKey, error) {
	if template.Subject.CommonName == "" {
		return nil, nil, nil, fmt.Errorf("subject common name must be set")
	}

	serialNumber, err := createSerialNumber()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate serial number: %w", err)
	}

	var maxPathLenZero bool
	if template.MaxPathLen > 0 {
		maxPathLenZero = false
	} else {
		maxPathLenZero = true
	}

	template.SerialNumber = serialNumber
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(validity)
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.MaxPathLenZero = maxPathLenZero

	publicKey, privateKey, err := createKeyPair(publicKeyAlgorithm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	cert, certPEM, err := createCert(template, issuerCert, publicKey, issuerPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	return cert, certPEM, privateKey, nil
}

func createEndEntityCert(template, issuerCert *x509.Certificate, issuerPrivateKey crypto.PrivateKey, publicKeyAlgorithm x509.PublicKeyAlgorithm, validity time.Duration) (*x509.Certificate, []byte, crypto.PrivateKey, error) {
	if template.Subject.CommonName == "" {
		return nil, nil, nil, fmt.Errorf("subject common name must be set")
	}

	serialNumber, err := createSerialNumber()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate serial number: %w", err)
	}

	template.SerialNumber = serialNumber
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(validity)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template.IsCA = false
	template.MaxPathLenZero = true

	publicKey, privateKey, err := createKeyPair(publicKeyAlgorithm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	cert, certPEM, err := createCert(template, issuerCert, publicKey, issuerPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cert: %w", err)
	}

	return cert, certPEM, privateKey, nil
}

func createKeyPair(publicKeyAlgorithm x509.PublicKeyAlgorithm) (crypto.PublicKey, crypto.PrivateKey, error) {
	var publicKey crypto.PublicKey
	var privateKey crypto.PrivateKey

	switch publicKeyAlgorithm {

	case x509.RSA:
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate rsa private key: %w", err)
		}
		publicKey = &rsaPrivateKey.PublicKey
		privateKey = rsaPrivateKey

	case x509.Ed25519:
		ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
		}
		publicKey = ed25519PublicKey
		privateKey = ed25519PrivateKey

	default:
		return nil, nil, fmt.Errorf("unsupported public key algorithm")
	}

	return publicKey, privateKey, nil
}

func createCert(template, issuer *x509.Certificate, subjectPublicKey crypto.PublicKey, issuerPrivateKey crypto.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, subjectPublicKey, issuerPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPEM := pem.EncodeToMemory(&b)

	return cert, certPEM, err
}

func createSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 256)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
