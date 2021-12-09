package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gitlab.com/testifysec/witness/pkg/attestation"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	Name = "JWT"
	Type = "https://witness.testifysec.com/attestations/JWT/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
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
