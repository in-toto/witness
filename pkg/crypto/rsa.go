package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
)

type RSASigner struct {
	priv *rsa.PrivateKey
	hash crypto.Hash
}

func NewRSASigner(priv *rsa.PrivateKey, hash crypto.Hash) *RSASigner {
	return &RSASigner{priv, hash}
}

func (s *RSASigner) KeyID() (string, error) {
	return GeneratePublicKeyID(&s.priv.PublicKey, s.hash)
}

func (s *RSASigner) Sign(r io.Reader) ([]byte, error) {
	digest, err := Digest(r, s.hash)
	if err != nil {
		return nil, err
	}

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       s.hash,
	}

	return rsa.SignPSS(rand.Reader, s.priv, s.hash, digest, opts)
}

type RSAVerifier struct {
	pub  *rsa.PublicKey
	hash crypto.Hash
}

func NewRSAVerifier(pub *rsa.PublicKey, hash crypto.Hash) *RSAVerifier {
	return &RSAVerifier{pub, hash}
}

func (v *RSAVerifier) KeyID() (string, error) {
	return GeneratePublicKeyID(v.pub, v.hash)
}

func (v *RSAVerifier) Verify(data io.Reader, sig []byte, opts ...VerifierOpts) error {
	digest, err := Digest(data, v.hash)
	if err != nil {
		return err
	}

	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       v.hash,
	}

	return rsa.VerifyPSS(v.pub, v.hash, digest, sig, pssOpts)
}
