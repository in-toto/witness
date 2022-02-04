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
	"time"
)

type Verifier interface {
	KeyIdentifier
	Verify(body io.Reader, sig []byte) error
	Bytes() ([]byte, error)
}

type VerifierOption func(*verifierOptions)

type verifierOptions struct {
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	hash          crypto.Hash
	trustedTime   time.Time
}

func VerifyWithRoots(roots []*x509.Certificate) VerifierOption {
	return func(vo *verifierOptions) {
		vo.roots = roots
	}
}

func VerifyWithIntermediates(intermediates []*x509.Certificate) VerifierOption {
	return func(vo *verifierOptions) {
		vo.intermediates = intermediates
	}
}

func VerifyWithHash(h crypto.Hash) VerifierOption {
	return func(vo *verifierOptions) {
		vo.hash = h
	}
}

func VerifyWithTrustedTime(t time.Time) VerifierOption {
	return func(vo *verifierOptions) {
		vo.trustedTime = t
	}
}

func NewVerifier(pub interface{}, opts ...VerifierOption) (Verifier, error) {
	options := &verifierOptions{
		hash: crypto.SHA256,
	}

	for _, opt := range opts {
		opt(options)
	}

	switch key := pub.(type) {
	case *rsa.PublicKey:
		return NewRSAVerifier(key, options.hash), nil
	case *ecdsa.PublicKey:
		return NewECDSAVerifier(key, options.hash), nil
	case ed25519.PublicKey:
		return NewED25519Verifier(key), nil
	case *x509.Certificate:
		return NewX509Verifier(key, options.intermediates, options.roots, options.trustedTime)
	default:
		return nil, ErrUnsupportedKeyType{
			t: fmt.Sprintf("%T", pub),
		}
	}
}

func NewVerifierFromReader(r io.Reader, opts ...VerifierOption) (Verifier, error) {
	key, err := TryParseKeyFromReader(r)
	if err != nil {
		return nil, err
	}

	return NewVerifier(key, opts...)
}
