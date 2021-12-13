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
