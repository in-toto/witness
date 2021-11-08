package pkg

import (
	"fmt"
	"io"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
)

func Verify(r io.Reader, verifiers ...crypto.Verifier) error {
	envelope, err := dsse.Decode(r)
	if err != nil {
		return fmt.Errorf("could not parse dsse envelope: %v", err)
	}

	return envelope.Verify(verifiers...)
}
