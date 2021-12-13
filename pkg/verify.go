package pkg

import (
	"fmt"
	"io"

	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
)

func VerifySignature(r io.Reader, verifiers ...cryptoutil.Verifier) (dsse.Envelope, error) {
	envelope, err := dsse.Decode(r)
	if err != nil {
		return envelope, fmt.Errorf("could not parse dsse envelope: %v", err)
	}

	return envelope, envelope.Verify(verifiers...)
}
