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

package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
)

type ErrUnsupportedKeyType struct {
	t string
}

func (e ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("unsupported signer key type: %v", e.t)
}

type Signer interface {
	KeyIdentifier
	Sign(r io.Reader) ([]byte, error)
	Verifier() (Verifier, error)
}

type KeyIdentifier interface {
	KeyID() (string, error)
}

type TrustBundler interface {
	Certificate() *x509.Certificate
	Intermediates() []*x509.Certificate
	Roots() []*x509.Certificate
}

type SignerOption func(*signerOptions)

type signerOptions struct {
	cert          *x509.Certificate
	intermediates []*x509.Certificate
	roots         []*x509.Certificate
	hash          crypto.Hash
}

func SignWithCertificate(cert *x509.Certificate) SignerOption {
	return func(so *signerOptions) {
		so.cert = cert
	}
}

func SignWithIntermediates(intermediates []*x509.Certificate) SignerOption {
	return func(so *signerOptions) {
		so.intermediates = intermediates
	}
}

func SignWithRoots(roots []*x509.Certificate) SignerOption {
	return func(so *signerOptions) {
		so.roots = roots
	}
}

func SignWithHash(h crypto.Hash) SignerOption {
	return func(so *signerOptions) {
		so.hash = h
	}
}

func NewSigner(priv interface{}, opts ...SignerOption) (Signer, error) {
	options := &signerOptions{
		hash: crypto.SHA256,
	}

	for _, opt := range opts {
		opt(options)
	}

	var signer Signer
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		signer = NewRSASigner(key, options.hash)
	case *ecdsa.PrivateKey:
		signer = NewECDSASigner(key, options.hash)
	case ed25519.PrivateKey:
		signer = NewED25519Signer(key)
	default:
		return nil, ErrUnsupportedKeyType{
			t: fmt.Sprintf("%T", priv),
		}
	}

	if options.cert != nil {
		return NewX509Signer(signer, options.cert, options.intermediates, options.roots)
	}

	return signer, nil
}

func NewSignerFromReader(r io.Reader, opts ...SignerOption) (Signer, error) {
	key, err := TryParseKeyFromReader(r)
	if err != nil {
		return nil, err
	}

	return NewSigner(key, opts...)
}
