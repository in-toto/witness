package pkg

import (
	"io"

	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
)

func Sign(r io.Reader, dataType string, w io.Writer, signers ...cryptoutil.Signer) error {
	env, err := dsse.Sign(dataType, r, signers...)
	if err != nil {
		return err
	}

	return env.Encode(w)
}
