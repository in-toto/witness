package crypto

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
	return GetPublicPemBytes(v.pub)
}
