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

type Verifier interface {
	KeyIdentifier
	Verify(body io.Reader, sig []byte) error
	Bytes() ([]byte, error)
}

func NewVerifier(pub interface{}) (Verifier, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		// todo: make the hash and other options configurable
		return NewRSAVerifier(key, crypto.SHA256), nil
	case *ecdsa.PublicKey:
		return NewECDSAVerifier(key, crypto.SHA256), nil
	case ed25519.PublicKey:
		return NewED25519Verifier(key), nil
	case *x509.Certificate:
		return NewX509Verifier(key, nil, nil)
	default:
		return nil, ErrUnsupportedKeyType{
			t: fmt.Sprintf("%T", pub),
		}
	}
}

func NewVerifierFromReader(r io.Reader) (Verifier, error) {
	key, err := TryParseKeyFromReader(r)
	if err != nil {
		return nil, err
	}

	return NewVerifier(key)
}
