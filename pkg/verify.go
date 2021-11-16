package pkg

import (
	"fmt"
	"io"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
)

func VerifySignature(r io.Reader, verifiers ...crypto.Verifier) (dsse.Envelope, error) {
	envelope, err := dsse.Decode(r)
	if err != nil {
		return envelope, fmt.Errorf("could not parse dsse envelope: %v", err)
	}

	return envelope, envelope.Verify(verifiers...)
}
