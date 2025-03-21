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

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/file"
	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	keybits = 512
)

func Test_loadOutfile(t *testing.T) {
	// Test with a specific file path
	t.Run("specific output file", func(t *testing.T) {
		tempDir := t.TempDir()
		outfile := filepath.Join(tempDir, "outfile.txt")

		f, err := loadOutfile(outfile)
		require.NoError(t, err)
		assert.Equal(t, outfile, f.Name())
		f.Close()
		os.Remove(outfile)
	})

	// Test with empty path (should use stdout)
	t.Run("stdout", func(t *testing.T) {
		f, err := loadOutfile("")
		require.NoError(t, err)
		assert.Equal(t, os.Stdout, f)
	})
}

func Test_New(t *testing.T) {
	cmd := New()
	require.NotNil(t, cmd)
	
	// Basic validation of command properties
	assert.Equal(t, "witness", cmd.Use)
	assert.Equal(t, true, cmd.SilenceErrors)
	assert.Equal(t, true, cmd.DisableAutoGenTag)
	
	// Verify that the expected subcommands are present
	expectedCmds := []string{"run", "sign", "verify", "completion", "version", "attestors"}
	
	// Get all command names
	foundCmds := make([]string, 0, len(cmd.Commands()))
	for _, subcmd := range cmd.Commands() {
		// Get just the first part of the Use string (e.g., "run" from "run [cmd]")
		parts := strings.Split(subcmd.Use, " ")
		foundCmds = append(foundCmds, parts[0])
	}
	
	// Check that all expected commands are found
	for _, expected := range expectedCmds {
		found := false
		for _, cmdName := range foundCmds {
			if cmdName == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected subcommand not found: %s", expected)
	}
}

func Test_loadSignersKeyPair(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		privatePem, _ := rsakeypair(t)
		signerOptions := options.SignerOptions{}
		signerOptions["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
			func(sp signer.SignerProvider) (signer.SignerProvider, error) {
				fsp := sp.(file.FileSignerProvider)
				fsp.KeyPath = privatePem.Name()
				return fsp, nil
			},
		}

		signers, err := loadSigners(context.Background(), signerOptions, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
		require.NoError(t, err)
		require.Len(t, signers, 1)
		assert.IsType(t, &cryptoutil.RSASigner{}, signers[0])
	})

	t.Run("failure", func(t *testing.T) {
		signerOptions := options.SignerOptions{}
		signerOptions["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
			func(sp signer.SignerProvider) (signer.SignerProvider, error) {
				fsp := sp.(file.FileSignerProvider)
				fsp.KeyPath = "not-a-file"
				return fsp, nil
			},
		}

		signers, err := loadSigners(context.Background(), signerOptions, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
		require.Error(t, err)
		require.Len(t, signers, 0)
	})
}

func Test_loadSignersCertificate(t *testing.T) {
	_, intermediates, leafcert, leafkey := fullChain(t)

	signerOptions := options.SignerOptions{}
	signerOptions["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
		func(sp signer.SignerProvider) (signer.SignerProvider, error) {
			fsp := sp.(file.FileSignerProvider)
			fsp.KeyPath = leafkey.Name()
			fsp.IntermediatePaths = []string{intermediates[0].Name()}
			fsp.CertPath = leafcert.Name()
			return fsp, nil
		},
	}

	signers, err := loadSigners(context.Background(), signerOptions, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
	require.NoError(t, err)
	require.Len(t, signers, 1)
	require.IsType(t, &cryptoutil.X509Signer{}, signers[0])
}

func rsakeypair(t *testing.T) (privatePem *os.File, publicPem *os.File) {
	privatekey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		t.Fatal(err)
	}

	publickey := &privatekey.PublicKey

	privatekey_bytes := x509.MarshalPKCS1PrivateKey(privatekey)

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privatekey_bytes,
	}

	workingDir := t.TempDir()

	privatePem, err = os.CreateTemp(workingDir, "key.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publickey),
	}

	publicPem, err = os.CreateTemp(workingDir, "key.pub")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		t.Fatal(err)
	}

	return privatePem, publicPem

}

// ref: https://jamielinux.com/docs/openssl-certificate-authority/appendix/intermediate-configuration-file.html
func fullChain(t *testing.T) (caPem *os.File, intermediatePems []*os.File, leafPem *os.File, leafkeyPem *os.File) {
	workingDir := t.TempDir()

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			Organization: []string{"Witness Testing"},
			CommonName:   "Witness Testing CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		t.Fatal(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	caPem, err = os.CreateTemp(workingDir, "ca.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(caPem, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		t.Fatal(err)
	}

	//common name must be different than the CA name
	intermediate := &x509.Certificate{
		SerialNumber: big.NewInt(43),
		Subject: pkix.Name{
			Organization: []string{"Witness Testing"},
			CommonName:   "Witness Testing Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	intermediatePrivateKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		t.Fatal(err)
	}

	intermediateCertBytes, err := x509.CreateCertificate(rand.Reader, intermediate, ca, &intermediatePrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	intermediatePem, err := os.CreateTemp(workingDir, "intermediate.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(intermediatePem, &pem.Block{Type: "CERTIFICATE", Bytes: intermediateCertBytes})
	if err != nil {
		t.Fatal(err)
	}

	intermediatePems = []*os.File{intermediatePem}

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(44),
		Subject: pkix.Name{
			Organization: []string{"Witness Testing"},
			CommonName:   "Witness Testing Leaf",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	leafPrivateKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		t.Fatal(err)
	}

	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leaf, intermediate, &leafPrivateKey.PublicKey, intermediatePrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	leafPem, err = os.CreateTemp(workingDir, "leaf.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(leafPem, &pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes})
	if err != nil {
		t.Fatal(err)
	}

	leafkeyPem, err = os.CreateTemp(workingDir, "leaf.key")

	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(leafkeyPem, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafPrivateKey)})
	if err != nil {
		t.Fatal(err)
	}

	return caPem, intermediatePems, leafPem, leafkeyPem

}