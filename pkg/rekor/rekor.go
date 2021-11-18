package rekor

import (
	"context"

	"github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/types"

	// imported so the init function runs
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
)

func StoreArtifact(rekorServer string, artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error) {
	client, err := client.GetRekorClient(rekorServer)
	if err != nil {
		return nil, err
	}

	entry, err := types.NewProposedEntry(context.Background(), "intoto", "0.0.1", types.ArtifactProperties{
		ArtifactBytes:  artifactBytes,
		PublicKeyBytes: pubkeyBytes,
	})

	if err != nil {
		return nil, err
	}

	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(entry)
	return client.Entries.CreateLogEntry(params)
}
