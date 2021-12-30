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
	"crypto/ed25519"
	"fmt"
	"io"
)

type ED25519Signer struct {
	priv ed25519.PrivateKey
}

func NewED25519Signer(priv ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{priv}
}

func (s *ED25519Signer) KeyID() (string, error) {
	return GeneratePublicKeyID(s.priv.Public(), crypto.SHA256)
}

func (s *ED25519Signer) Sign(r io.Reader) ([]byte, error) {
	msg, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(s.priv, msg), nil
}

func (s *ED25519Signer) Verifier() (Verifier, error) {
	pubKey := s.priv.Public()
	edPubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrUnsupportedKeyType{t: fmt.Sprintf("%T", edPubKey)}
	}

	return NewED25519Verifier(edPubKey), nil
}

type ED25519Verifier struct {
	pub ed25519.PublicKey
}

func NewED25519Verifier(pub ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{pub}
}

func (v *ED25519Verifier) KeyID() (string, error) {
	return GeneratePublicKeyID(v.pub, crypto.SHA256)
}

func (v *ED25519Verifier) Verify(r io.Reader, sig []byte) error {
	msg, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	verified := ed25519.Verify(v.pub, msg, sig)
	if !verified {
		return ErrVerifyFailed{}
	}

	return nil
}

func (v *ED25519Verifier) Bytes() ([]byte, error) {
	return PublicPemBytes(v.pub)
}
