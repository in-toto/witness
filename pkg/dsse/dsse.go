package dsse

import (
	"encoding/pem"
	"fmt"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
)

type ErrNoSignatures struct{}

func (e ErrNoSignatures) Error() string {
	return "no signatures in dsse envelope"
}

const PemTypeCertificate = "CERTIFICATE"

type Envelope struct {
	Payload     []byte      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID         []byte   `json:"keyid"`
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

func Sign(bodyType string, body []byte, signers ...crypto.Signer) (Envelope, error) {
	pae := preauthEncode(bodyType, body)
	env := Envelope{
		PayloadType: bodyType,
		Payload:     pae,
		Signatures:  make([]Signature, 0),
	}

	for _, signer := range signers {
		sig, err := signer.Sign(pae)
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
			leaf, intermediates := trustBundler.TrustBundle()
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
	if len(e.Signatures) == 0 {
		return ErrNoSignatures{}
	}

	for _, sig := range e.Signatures {
		for _, verifier := range verifiers {
			if err := verifier.Verify(e.Payload, sig.Signature); err != nil {
				return err
			}
		}
	}

	return nil
}
