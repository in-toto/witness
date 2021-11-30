package dsse

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
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
func Sign(bodyType string, body io.Reader, signers ...crypto.Signer) (Envelope, error) {
	env := Envelope{}
	// TODO: refactor this so we don't read the entire reader into memory.
	// the PAE has the length of the body as part of it, so path of least
	// resistance is just read all the bytes for now
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

		if trustBundler, ok := signer.(crypto.TrustBundler); ok {
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

func (e Envelope) Verify(verifiers ...crypto.Verifier) error {
	pae := preauthEncode(e.PayloadType, e.Payload)
	if len(e.Signatures) == 0 {
		return ErrNoSignatures{}
	}

	matchingSigFound := false
	for _, sig := range e.Signatures {
		for _, verifier := range verifiers {
			if err := verifier.Verify(bytes.NewReader(pae), sig.Signature); err != nil {
				return err
			} else {
				matchingSigFound = true
			}
		}
	}

	if !matchingSigFound {
		return ErrNoMatchingSigs{}
	}

	return nil
}

func (e Envelope) Encode(w io.Writer) error {
	return json.NewEncoder(w).Encode(&e)
}

func Decode(r io.Reader) (Envelope, error) {
	env := Envelope{}
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&env)
	return env, err
}
