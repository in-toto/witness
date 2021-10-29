package crypto

import (
	"crypto"
	"crypto/x509"
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

func Digest(data []byte, hash crypto.Hash) ([]byte, error) {
	hashFunc := hash.New()
	_, err := hashFunc.Write(data)
	if err != nil {
		return nil, err
	}

	return hashFunc.Sum(nil), nil
}

func GeneratePublicKeyID(pub interface{}, hash crypto.Hash) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	return Digest(pemBytes, hash)
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
