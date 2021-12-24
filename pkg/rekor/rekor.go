// Copyright 2021 The TestifySec Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
