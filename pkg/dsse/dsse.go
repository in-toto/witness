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

package dsse

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/testifysec/witness/pkg/cryptoutil"
)

type ErrNoSignatures struct{}

func (e ErrNoSignatures) Error() string {
	return "no signatures in dsse envelope"
}

type ErrNoMatchingSigs struct{}

func (e ErrNoMatchingSigs) Error() string {
	return "no valid signatures for the provided verifiers found"
}

const PemTypeCertificate = "CERTIFICATE"

type Envelope struct {
	Payload     []byte      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID         string   `json:"keyid"`
	Signature     []byte   `json:"sig"`
	Certificate   []byte   `json:"certificate,omitempty"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

// preauthEncode wraps the data to be signed or verified and it's type in the DSSE protocol's
// pre-authentication encoding as detailed at https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
func preauthEncode(bodyType string, body []byte) []byte {
	const dsseVersion = "DSSEv1"
	return []byte(fmt.Sprintf("%s %d %s %d %s", dsseVersion, len(bodyType), bodyType, len(body), body))
}

// TODO: it'd be nice to break some of this logic out of what should be a presentation layer only
func Sign(bodyType string, body io.Reader, signers ...cryptoutil.Signer) (Envelope, error) {
	env := Envelope{}
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return env, err
	}

	env.PayloadType = bodyType
	env.Payload = bodyBytes
	env.Signatures = make([]Signature, 0)
	pae := preauthEncode(bodyType, bodyBytes)
	for _, signer := range signers {
		sig, err := signer.Sign(bytes.NewReader(pae))
		if err != nil {
			return env, err
		}

		keyID, err := signer.KeyID()
		if err != nil {
			return env, err
		}

		dsseSig := Signature{
			KeyID:     keyID,
			Signature: sig,
		}

		if trustBundler, ok := signer.(cryptoutil.TrustBundler); ok {
			leaf := trustBundler.Certificate()
			intermediates := trustBundler.Intermediates()
			if leaf != nil {
				dsseSig.Certificate = pem.EncodeToMemory(&pem.Block{Type: PemTypeCertificate, Bytes: leaf.Raw})
			}

			for _, intermediate := range intermediates {
				dsseSig.Intermediates = append(dsseSig.Intermediates, pem.EncodeToMemory(&pem.Block{Type: PemTypeCertificate, Bytes: intermediate.Raw}))
			}
		}

		env.Signatures = append(env.Signatures, dsseSig)
	}

	return env, nil
}

type VerificationOption func(*verificationOptions)

type verificationOptions struct {
	roots         []*x509.Certificate
	intermediates []*x509.Certificate
	verifiers     []cryptoutil.Verifier
	trustedTime   time.Time
}

func WithRoots(roots []*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.roots = roots
	}
}

func WithIntermediates(intermediates []*x509.Certificate) VerificationOption {
	return func(vo *verificationOptions) {
		vo.intermediates = intermediates
	}
}

func WithVerifiers(verifiers []cryptoutil.Verifier) VerificationOption {
	return func(vo *verificationOptions) {
		vo.verifiers = verifiers
	}
}

func WithTrustedTime(time time.Time) VerificationOption {
	return func(vo *verificationOptions) {
		vo.trustedTime = time
	}
}

func (e Envelope) Verify(opts ...VerificationOption) ([]cryptoutil.Verifier, error) {
	options := &verificationOptions{}
	for _, opt := range opts {
		opt(options)
	}

	pae := preauthEncode(e.PayloadType, e.Payload)
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures{}
	}

	matchingSigFound := false
	passedVerifiers := make([]cryptoutil.Verifier, 0)
	for _, sig := range e.Signatures {
		if sig.Certificate != nil && len(sig.Certificate) > 0 {
			cert, err := TryParseCertificate(sig.Certificate)
			if err != nil {
				continue
			}

			sigIntermediates := make([]*x509.Certificate, 0)
			for _, int := range sig.Intermediates {
				intCert, err := TryParseCertificate(int)
				if err != nil {
					continue
				}

				sigIntermediates = append(sigIntermediates, intCert)
			}

			sigIntermediates = append(sigIntermediates, options.intermediates...)
			verifier, err := cryptoutil.NewX509Verifier(cert, sigIntermediates, options.roots, options.trustedTime)
			if err != nil {
				return nil, err
			}

			if err := verifier.Verify(bytes.NewReader(pae), sig.Signature); err != nil {
				return nil, err
			} else {
				passedVerifiers = append(passedVerifiers, verifier)
				matchingSigFound = true
			}
		}

		for _, verifier := range options.verifiers {
			if err := verifier.Verify(bytes.NewReader(pae), sig.Signature); err != nil {
				return nil, err
			} else {
				passedVerifiers = append(passedVerifiers, verifier)
				matchingSigFound = true
			}
		}
	}

	if !matchingSigFound {
		return nil, ErrNoMatchingSigs{}
	}

	return passedVerifiers, nil
}

func TryParseCertificate(data []byte) (*x509.Certificate, error) {
	possibleCert, err := cryptoutil.TryParseKeyFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	cert, ok := possibleCert.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("data was a valid verifier but not a certificate")
	}

	return cert, nil
}
