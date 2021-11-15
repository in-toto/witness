package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
)

type VerifierOpts interface {
	WithTrustBundle(leaf *x509.Certificate, intermediates []*x509.Certificate)
}

type Verifier interface {
	KeyIdentifier
	Verify(body io.Reader, sig []byte, opts ...VerifierOpts) error
	Bytes() ([]byte, error)
}

func NewVerifier(pub interface{}) (Verifier, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		// todo: make the hash and other options configurable
		return NewRSAVerifier(key, crypto.SHA256), nil
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
