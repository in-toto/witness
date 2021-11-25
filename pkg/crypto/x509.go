package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"io"
)

type X509Verifier struct {
	cert          *x509.Certificate
	roots         *x509.CertPool
	intermediates *x509.CertPool
	verifier      Verifier
}

func NewX509Verifier(cert *x509.Certificate, roots, intermediates *x509.CertPool) (*X509Verifier, error) {
	verifier, err := NewVerifier(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &X509Verifier{
		cert:          cert,
		roots:         roots,
		intermediates: intermediates,
		verifier:      verifier,
	}, nil
}

func (v *X509Verifier) KeyID() (string, error) {
	return v.verifier.KeyID()
}

func (v *X509Verifier) Verify(body io.Reader, sig []byte) error {
	if _, err := v.cert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.intermediates,
	}); err != nil {
		return err
	}

	return v.verifier.Verify(body, sig)
}

func (v *X509Verifier) Bytes() ([]byte, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.cert.Raw})
	return pemBytes, nil
}
