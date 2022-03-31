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
	"crypto/x509"
	"encoding/pem"
	"io"
	"time"
)

type X509Verifier struct {
	cert          *x509.Certificate
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	verifier      Verifier
	trustedTime   time.Time
}

func NewX509Verifier(cert *x509.Certificate, intermediates, roots []*x509.Certificate, trustedTime time.Time) (*X509Verifier, error) {
	verifier, err := NewVerifier(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &X509Verifier{
		cert:          cert,
		roots:         roots,
		intermediates: intermediates,
		verifier:      verifier,
		trustedTime:   trustedTime,
	}, nil
}

func (v *X509Verifier) KeyID() (string, error) {
	return v.verifier.KeyID()
}

func (v *X509Verifier) Verify(body io.Reader, sig []byte) error {
	rootPool := certificatesToPool(v.roots)
	intermediatePool := certificatesToPool(v.intermediates)
	if _, err := v.cert.Verify(x509.VerifyOptions{
		CurrentTime:   v.trustedTime,
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return err
	}

	return v.verifier.Verify(body, sig)
}

func (v *X509Verifier) BelongsToRoot(root *x509.Certificate) error {
	rootPool := certificatesToPool([]*x509.Certificate{root})
	intermediatePool := certificatesToPool(v.intermediates)
	_, err := v.cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.trustedTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	return err
}

func (v *X509Verifier) Bytes() ([]byte, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.cert.Raw})
	return pemBytes, nil
}

func (v *X509Verifier) Certificate() *x509.Certificate {
	return v.cert
}

func (v *X509Verifier) Intermediates() []*x509.Certificate {
	return v.intermediates
}

func (v *X509Verifier) Roots() []*x509.Certificate {
	return v.roots
}

type X509Signer struct {
	cert          *x509.Certificate
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	signer        Signer
}

type ErrInvalidSigner struct{}

func (e ErrInvalidSigner) Error() string {
	return "signer must not be nil"
}

type ErrInvalidCertificate struct{}

func (e ErrInvalidCertificate) Error() string {
	return "certificate must not be nil"
}

func NewX509Signer(signer Signer, cert *x509.Certificate, intermediates, roots []*x509.Certificate) (*X509Signer, error) {
	if signer == nil {
		return nil, ErrInvalidSigner{}
	}

	if cert == nil {
		return nil, ErrInvalidCertificate{}
	}

	return &X509Signer{
		signer:        signer,
		cert:          cert,
		roots:         roots,
		intermediates: intermediates,
	}, nil
}

func (s *X509Signer) KeyID() (string, error) {
	return s.signer.KeyID()
}

func (s *X509Signer) Sign(r io.Reader) ([]byte, error) {
	return s.signer.Sign(r)
}

func (s *X509Signer) Verifier() (Verifier, error) {
	verifier, err := s.signer.Verifier()
	if err != nil {
		return nil, err
	}

	return &X509Verifier{
		verifier:      verifier,
		cert:          s.cert,
		roots:         s.roots,
		intermediates: s.intermediates,
	}, nil
}

func (s *X509Signer) Certificate() *x509.Certificate {
	return s.cert
}

func (s *X509Signer) Intermediates() []*x509.Certificate {
	return s.intermediates
}

func (s *X509Signer) Roots() []*x509.Certificate {
	return s.roots
}

func certificatesToPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool
}
