// Copyright 2022 The Witness Contributors
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

package fulcio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"

	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	sigo "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

func GetSigner(ctx context.Context, funcioURL string, oidcIssuer string, oidcClientID string) (cryptoutil.Signer, error) {
	fClient, err := newClient(funcioURL)
	if err != nil {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	fulcioSigner, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	certResp, err := getCert(fulcioSigner.(*signature.RSAPKCS1v15Signer), fClient, oidcIssuer, oidcClientID)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certResp.CertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	intermediates := []*x509.Certificate{}
	roots := []*x509.Certificate{}

	rest := certResp.ChainPEM

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("failed to parse certificate PEM")
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to parse certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch cert.IsCA {
		case true:
			roots = append(roots, cert)
		default:
			intermediates = append(intermediates, cert)
		}

	}

	ss := cryptoutil.NewRSASigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	witnessSigner, err := cryptoutil.NewX509Signer(ss, leaf, intermediates, roots)
	if err != nil {
		return nil, err
	}
	return witnessSigner, nil
}

func getCert(signer *signature.RSAPKCS1v15Signer, fc api.Client, oidcIssuer string, oidcClientID string) (*api.CertificateResponse, error) {
	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	b := bytes.NewBuffer([]byte(tok.Subject))
	proof, err := signer.SignMessage(b, sigo.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		log.Fatal(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: "rsa4096",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}
	return fc.SigningCert(cr, tok.RawString)
}

func newClient(fulcioURL string) (api.Client, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	fClient := api.NewClient(fulcioServer, api.WithUserAgent("witness"))
	return fClient, nil
}
