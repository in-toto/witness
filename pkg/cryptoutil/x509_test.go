// Copyright 2021 The TestifySec Authors
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

package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createRsaKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}

func createCert(priv, pub interface{}, temp, parent *x509.Certificate) (*x509.Certificate, error) {
	var err error
	temp.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, temp, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func createRoot() (*x509.Certificate, interface{}, error) {
	priv, pub, err := createRsaKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            2,
	}

	cert, err := createCert(priv, pub, template, template)
	return cert, priv, err
}

func createIntermediate(parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, interface{}, error) {
	priv, pub, err := createRsaKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Intermediate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}

	cert, err := createCert(parentPriv, pub, template, parent)
	return cert, priv, err
}

func createLeaf(parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, interface{}, error) {
	priv, pub, err := createRsaKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Leaf",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	cert, err := createCert(parentPriv, pub, template, parent)
	return cert, priv, err
}

func TestX509(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intPriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, priv, err := createLeaf(intermediate, intPriv)
	require.NoError(t, err)

	signer, err := NewX509Signer(priv, leaf, []*x509.Certificate{intermediate}, []*x509.Certificate{root})
	require.NoError(t, err)

	data := []byte("this is some test data")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	verifier, err := NewX509Verifier(leaf, []*x509.Certificate{intermediate}, []*x509.Certificate{root})
	require.NoError(t, err)
	err = verifier.Verify(bytes.NewReader(data), sig)
	assert.NoError(t, err)
	err = verifier.Verify(bytes.NewReader([]byte("this is not the signed data")), sig)
	assert.Error(t, err)

	verifier, err = NewX509Verifier(leaf, []*x509.Certificate{intermediate}, nil)
	require.NoError(t, err)
	err = verifier.Verify(bytes.NewReader(data), sig)
	assert.Error(t, err)

}
