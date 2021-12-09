package pkg

import (
	"io"

	"github.com/testifysec/witness/pkg/crypto"
	"github.com/testifysec/witness/pkg/dsse"
)

func Sign(r io.Reader, dataType string, w io.Writer, signers ...crypto.Signer) error {
	env, err := dsse.Sign(dataType, r, signers...)
	if err != nil {
		return err
	}

	return env.Encode(w)
}
