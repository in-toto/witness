// Copyright 2021 The Witness Contributors
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"strings"

	// imported so the init function runs
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
)

type wrappedRekorClient struct {
	*generatedClient.Rekor
}

type IRekorOperations interface {
	StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error)
	FindTLogEntriesByPayload(payload []byte) (*models.LogEntryAnon, error)
}

var _ IRekorOperations = (*wrappedRekorClient)(nil)

func New(rekorServer string) (IRekorOperations, error) {
	client, err := client.GetRekorClient(rekorServer)
	if err != nil {
		return nil, err
	}

	return &wrappedRekorClient{
		Rekor: client,
	}, nil
}

func (r *wrappedRekorClient) StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error) {
	entry, err := types.NewProposedEntry(context.Background(), "intoto", "0.0.1", types.ArtifactProperties{
		ArtifactBytes:  artifactBytes,
		PublicKeyBytes: pubkeyBytes,
	})

	if err != nil {
		return nil, err
	}

	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(entry)
	return r.Entries.CreateLogEntry(params)
}

func (r *wrappedRekorClient) getTlogEntry(uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.SetEntryUUID(uuid)
	resp, err := r.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for _, e := range resp.Payload {
		return &e, nil
	}
	return nil, errors.New("empty response")
}

func (r *wrappedRekorClient) FindTLogEntriesByPayload(payload []byte) (*models.LogEntryAnon, error) {
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	searchIndex, err := r.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}

	uuids := searchIndex.GetPayload()

	if len(uuids) == 0 {
		return nil, nil
	}

	logEntry, err := r.getTlogEntry(uuids[0])
	if err != nil {
		return nil, err
	}

	return logEntry, nil
}
