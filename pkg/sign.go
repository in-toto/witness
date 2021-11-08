package pkg

import (
	"io"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/dsse"
)

func Sign(r io.Reader, dataType string, w io.Writer, signers ...crypto.Signer) error {
	env, err := dsse.Sign(dataType, r, signers...)
	if err != nil {
		return err
	}

	return env.Encode(w)
}
