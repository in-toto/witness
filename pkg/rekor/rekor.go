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
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
)

var (
	rekorSupportedHashes = map[crypto.Hash]string{crypto.SHA256: "sha256", crypto.SHA1: "sha1"}
)

type wrappedRekorClient struct {
	*generatedClient.Rekor
}

type RekorClient interface {
	StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error)
	FindEntriesBySubject(cryptoutil.DigestSet) ([]*models.LogEntryAnon, error)
}

func New(rekorServer string) (RekorClient, error) {
	client, err := client.GetRekorClient(rekorServer)
	if err != nil {
		return nil, err
	}

	return &wrappedRekorClient{
		Rekor: client,
	}, nil
}

func (r *wrappedRekorClient) StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error) {
	entry, err := types.NewProposedEntry(context.Background(), "dsse", "0.0.1", types.ArtifactProperties{
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

func (r *wrappedRekorClient) FindEntriesBySubject(subjectDigestSet cryptoutil.DigestSet) ([]*models.LogEntryAnon, error) {
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{}

	for hash, digest := range subjectDigestSet {
		if rekorHash, ok := rekorSupportedHashes[hash]; ok {
			params.Query.Hash = fmt.Sprintf("%v:%v", rekorHash, digest)
			break
		}
	}

	searchIndex, err := r.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}

	uuids := searchIndex.GetPayload()
	entries := make([]*models.LogEntryAnon, 0)
	for _, uuid := range uuids {
		entry, err := r.getTlogEntry(uuid)
		if err != nil {
			continue
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func ParseEnvelopeFromEntry(entry *models.LogEntryAnon) (dsse.Envelope, error) {
	env := dsse.Envelope{}
	if entry.Attestation == nil {
		return env, errors.New("empty or invalid attestation")
	}

	bodyStr, ok := entry.Body.(string)
	if !ok {
		return env, errors.New("invalid body")
	}

	decodedBody, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		return env, fmt.Errorf("failed to decode body: %w", err)
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(decodedBody), runtime.JSONConsumer())
	if err != nil {
		return env, fmt.Errorf("couldn't parse rekor entry: %w", err)
	}

	baseModel := models.Dsse{}
	if err := baseModel.UnmarshalJSON(decodedBody); err != nil {
		return env, fmt.Errorf("failed to parse rekor entry: %w", err)
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return env, fmt.Errorf("failed to get entry from rekor: %w", err)
	}

	dsseEntry, ok := eimpl.(*rekordsse.V001Entry)
	if !ok {
		return env, errors.New("rekor entry isn't a dsse entry")
	}

	env.Payload = entry.Attestation.Data
	env.PayloadType = *dsseEntry.DsseObj.PayloadType
	for _, sig := range dsseEntry.DsseObj.Signatures {
		decodedSig, err := base64.StdEncoding.DecodeString(string(sig.Sig))
		if err != nil {
			return env, fmt.Errorf("failed to decode signature: %w", err)
		}

		verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(sig.PublicKey), cryptoutil.VerifyWithTrustedTime(time.Unix(*entry.IntegratedTime, 0)))
		if err != nil {
			return env, fmt.Errorf("failed to create verifier from public key on rekor entry: %w", err)
		}

		envSig := dsse.Signature{
			Signature: decodedSig,
			KeyID:     sig.Keyid,
		}

		_, ok := verifier.(*cryptoutil.X509Verifier)
		if ok {
			envSig.Certificate = sig.PublicKey
		}

		env.Signatures = append(env.Signatures, envSig)
	}

	return env, nil
}
