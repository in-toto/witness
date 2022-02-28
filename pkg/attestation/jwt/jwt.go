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

package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/testifysec/witness/pkg/attestation"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	Name    = "jwt"
	Type    = "https://witness.dev/attestations/jwt/v0.1"
	RunType = attestation.PreRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type ErrInvalidToken string

func (e ErrInvalidToken) Error() string {
	return fmt.Sprintf("invalid token: \"%v\"", string(e))
}

type Option func(a *Attestor)

type VerificationInfo struct {
	JWKSUrl string          `json:"jwksUrl"`
	JWK     jose.JSONWebKey `json:"jwk"`
}

type Attestor struct {
	Claims     map[string]interface{} `json:"claims"`
	VerifiedBy VerificationInfo       `json:"verifiedBy,omitempty"`
	jwksUrl    string
	token      string
}

func WithToken(token string) Option {
	return func(a *Attestor) {
		a.token = token
	}
}

func WithJWKSUrl(url string) Option {
	return func(a *Attestor) {
		a.jwksUrl = url
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		Claims: make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if a.token == "" {
		return ErrInvalidToken(a.token)
	}

	parsed, err := jwt.ParseSigned(a.token)
	if err != nil {
		return err
	}

	resp, err := http.Get(a.jwksUrl)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	jwks := jose.JSONWebKeySet{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&jwks); err != nil {
		return err
	}

	if err := parsed.Claims(jwks, &a.Claims); err != nil {
		return err
	}

	keyID := ""
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	possibleJwk := jwks.Key(keyID)
	if len(possibleJwk) <= 0 {
		return nil
	}

	a.VerifiedBy = VerificationInfo{
		JWKSUrl: a.jwksUrl,
		JWK:     possibleJwk[0],
	}

	return nil
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}
