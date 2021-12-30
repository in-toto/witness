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

func NewSigner(priv interface{}) (Signer, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		// todo: make the hash and other options configurable
		return NewRSASigner(key, crypto.SHA256), nil
	case *ecdsa.PrivateKey:
		return NewECDSASigner(key, crypto.SHA256), nil
	case ed25519.PrivateKey:
		return NewED25519Signer(key), nil
	default:
		return nil, ErrUnsupportedKeyType{
			t: fmt.Sprintf("%T", priv),
		}
	}
}

func NewSignerFromReader(r io.Reader) (Signer, error) {
	key, err := TryParseKeyFromReader(r)
	if err != nil {
		return nil, err
	}

	return NewSigner(key)
}
