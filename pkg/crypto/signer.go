package crypto

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
