// Copyright 2021 The Witness Contributors
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

const (
	keybits = 512
)

func Test_fileVerifier(t *testing.T) {
	privatePem, publicPem := rsakeypair(t)
	defer privatePem.Close()
	defer publicPem.Close()

	caPem, intermediatePems, leafPem, leafkeyPem := fullChain(t)
	defer caPem.Close()
	defer leafPem.Close()
	defer leafkeyPem.Close()
	for _, intermediatePem := range intermediatePems {
		defer intermediatePem.Close()
	}

	_, err := fileVerifier(leafPem.Name())
	if err != nil {
		t.Fatal(err)
	}

	_, err = fileVerifier(publicPem.Name())
	if err != nil {
		t.Fatal(err)
	}

}

func Test_caVerifier(t *testing.T) {
	caPem, intermediatePems, leafPem, leafkeyPem := fullChain(t)

	defer leafPem.Close()
	defer leafkeyPem.Close()
	for _, intermediatePem := range intermediatePems {
		defer intermediatePem.Close()
	}

	caPems := []string{caPem.Name()}

	// f, err := os.Open(caPem.Name())
	// if err != nil {
	// 	t.Fatal(err)

	// }

	// b, err := ioutil.ReadAll(f)
	// if err != nil {
	// 	t.Fatal(err)

	// }

	// fmt.Printf("%s\n", b)

	// block, _ := pem.Decode(b)
	// if block == nil {
	// 	t.Fatal("failed to decode PEM block")
	// }

	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// spew.Dump(cert)

	caVerifier(caPems)

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

	privatePem, err = os.CreateTemp("/tmp", "key.pem")
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

	publicPem, err = os.CreateTemp("/tmp", "key.pub")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		t.Fatal(err)
	}

	return privatePem, publicPem

}

//ref: https://jamielinux.com/docs/openssl-certificate-authority/appendix/intermediate-configuration-file.html
func fullChain(t *testing.T) (caPem *os.File, intermediatePems []*os.File, leafPem *os.File, leafkeyPem *os.File) {
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

	caPem, err = os.CreateTemp("/tmp", "ca.pem")
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

	intermediatePem, err := os.CreateTemp("/tmp", "intermediate.pem")
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

	leafPem, err = os.CreateTemp("/tmp", "leaf.pem")
	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(leafPem, &pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes})
	if err != nil {
		t.Fatal(err)
	}

	leafkeyPem, err = os.CreateTemp("/tmp", "leaf.key")

	if err != nil {
		t.Fatal(err)
	}

	err = pem.Encode(leafkeyPem, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafPrivateKey)})
	if err != nil {
		t.Fatal(err)
	}

	return caPem, intermediatePems, leafPem, leafkeyPem

}
