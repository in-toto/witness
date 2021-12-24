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
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
)

type ErrUnsupportedPEM struct {
	t string
}

func (e ErrUnsupportedPEM) Error() string {
	return fmt.Sprintf("unsupported pem type: %v", e.t)
}

type ErrInvalidPemBlock struct{}

func (e ErrInvalidPemBlock) Error() string {
	return "invalid pem block"
}

func DigestBytes(data []byte, hash crypto.Hash) ([]byte, error) {
	return Digest(bytes.NewReader(data), hash)
}

func Digest(r io.Reader, hash crypto.Hash) ([]byte, error) {
	hashFunc := hash.New()
	if _, err := io.Copy(hashFunc, r); err != nil {
		return nil, err
	}

	return hashFunc.Sum(nil), nil
}

func HexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func GeneratePublicKeyID(pub interface{}, hash crypto.Hash) (string, error) {
	pemBytes, err := PublicPemBytes(pub)
	if err != nil {
		return "", err
	}

	digest, err := DigestBytes(pemBytes, hash)
	if err != nil {
		return "", err
	}

	return string(HexEncode(digest)), nil
}

func PublicPemBytes(pub interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return nil, err
	}

	return pemBytes, err
}

func TryParsePEMBlock(block *pem.Block) (interface{}, error) {
	if block == nil {
		return nil, ErrInvalidPemBlock{}
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, err
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, err
	}

	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, err
	}

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return key, err
	}

	key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return key, err
	}

	key, err = x509.ParseCertificate(block.Bytes)
	if err == nil {
		return key, err
	}

	return nil, ErrUnsupportedPEM{block.Type}
}

func TryParseKeyFromReader(r io.Reader) (interface{}, error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// we may want to handle files with multiple pem blocks in them, but for now...
	pemBlock, _ := pem.Decode(bytes)
	return TryParsePEMBlock(pemBlock)
}
