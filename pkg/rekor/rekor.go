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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/client"
	generatedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
	"github.com/testifysec/witness/pkg/intoto"
	"github.com/testifysec/witness/pkg/log"
)

const refString = "%s/api/v1/log/entries?logIndex=%d"

var (
	rekorSupportedHashes = map[crypto.Hash]string{crypto.SHA256: "sha256", crypto.SHA1: "sha1"}
	backRefs             = []string{
		"https://witness.dev/attestations/gitlab/v0.1/pipelineurl",
		"https://witness.dev/attestations/git/v0.1/commithash",
		"https://witness.dev/attestations/product/v0.1/file",
	}
)

type wrappedRekorClient struct {
	*generatedClient.Rekor
	url            string
	searchedHashes map[string]bool
	searchedIndex  map[string]bool
}

type RekorClient interface {
	StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error)
	FindEntriesBySubject(cryptoutil.DigestSet) ([]*models.LogEntryAnon, error)
	FindEvidence([]cryptoutil.DigestSet, dsse.Envelope, []cryptoutil.Verifier, []witness.CollectionEnvelope, int32) ([]witness.CollectionEnvelope, error)
}

func New(rekorServer string) (RekorClient, error) {
	client, err := client.GetRekorClient(rekorServer)
	if err != nil {
		return nil, err
	}

	return &wrappedRekorClient{
		Rekor:          client,
		url:            rekorServer,
		searchedHashes: map[string]bool{},
		searchedIndex:  map[string]bool{},
	}, nil
}

func (r *wrappedRekorClient) StoreArtifact(artifactBytes, pubkeyBytes []byte) (*entries.CreateLogEntryCreated, error) {
	entry, err := types.NewProposedEntry(context.Background(), "dsse", "0.0.1", types.ArtifactProperties{
		ArtifactBytes:  artifactBytes,
		PublicKeyBytes: pubkeyBytes,
	})

	if err != nil {
		fmt.Println("error creating entry:", err)
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

func (r *wrappedRekorClient) FindEvidence(subject []cryptoutil.DigestSet, policyEnvelope dsse.Envelope, verifier []cryptoutil.Verifier, verifiedEnvelopes []witness.CollectionEnvelope, recursionLimit int32) ([]witness.CollectionEnvelope, error) {

	entries := []*models.LogEntryAnon{}
	for _, ds := range subject {
		entry, err := r.FindEntriesBySubject(ds)
		if err != nil {
			return nil, err
		}

		for _, e := range entry {
			if !r.searchedIndex[fmt.Sprintf(refString, r.url, e.LogIndex)] {
				entries = append(entries, e)
			}
		}
	}

	var evidenceToVerify []witness.CollectionEnvelope

	for _, entry := range entries {

		envelope, err := ParseEnvelopeFromEntry(entry)
		if err != nil {
			return nil, err
		}

		reference := fmt.Sprintf(refString, r.url, *entry.LogIndex)

		collectionEnvelope := witness.CollectionEnvelope{
			Envelope:  envelope,
			Reference: reference,
		}

		evidenceToVerify = append(evidenceToVerify, collectionEnvelope)
	}

	veropt := witness.VerifyWithCollectionEnvelopes(append(verifiedEnvelopes, evidenceToVerify...))
	verifiedEvidence, err := witness.Verify(policyEnvelope, verifier, veropt)

	//remove dups

	if err == nil {
		deduped := map[string]witness.CollectionEnvelope{}

		for _, e := range verifiedEvidence {
			deduped[e.Reference] = e
		}

		verifiedEvidence = []witness.CollectionEnvelope{}
		for _, e := range deduped {
			verifiedEvidence = append(verifiedEvidence, e)
		}

		return verifiedEvidence, nil
	} else if recursionLimit > 0 {
		backrefSubjs, err := getBackRefSubjects(evidenceToVerify)
		if err != nil {
			return nil, err
		}
		return r.FindEvidence(backrefSubjs, policyEnvelope, verifier, verifiedEvidence, recursionLimit-1)
	}

	return nil, err
}

func getBackRefSubjects(verifiedEvidence []witness.CollectionEnvelope) ([]cryptoutil.DigestSet, error) {
	var backRefSubjects []cryptoutil.DigestSet

	subjects := []intoto.Subject{}

	for _, ce := range verifiedEvidence {
		statementBytes := ce.Envelope.Payload
		statement := intoto.Statement{}
		if err := json.Unmarshal(statementBytes, &statement); err != nil {
			return nil, err
		}

		subjects = append(subjects, statement.Subject...)

	}

	for _, subject := range subjects {
		for _, backRef := range backRefs {
			if strings.Contains(subject.Name, backRef) {
				log.Infof("Found backref %s", subject.Name)

				ds := cryptoutil.DigestSet{}
				for name, value := range subject.Digest {
					switch name {
					case "sha256":
						ds[crypto.SHA256] = value
					case "sha1":
						ds[crypto.SHA1] = value
					}
				}

				backRefSubjects = append(backRefSubjects, ds)
			}
		}
	}
	return backRefSubjects, nil
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

	if r.searchedHashes[params.Query.Hash] {
		return nil, nil
	}

	log.Infof("Searching for entries with subject hash: %s", params.Query.Hash)

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

	r.searchedHashes[params.Query.Hash] = true
	for _, entry := range entries {
		r.searchedIndex[fmt.Sprintf(refString, r.url, *entry.LogIndex)] = true
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

		trustedTime := time.Unix(*entry.IntegratedTime, 0)
		verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(sig.PublicKey), cryptoutil.VerifyWithTrustedTime(trustedTime))
		if err != nil {
			return env, fmt.Errorf("failed to create verifier from public key on rekor entry: %w", err)
		}

		envSig := dsse.NewSignature(sig.Keyid, decodedSig, dsse.SignatureWithTrustedTime(trustedTime))
		_, ok := verifier.(*cryptoutil.X509Verifier)
		if ok {
			envSig.Certificate = sig.PublicKey
			for _, intermediate := range sig.Intermediates {
				decoded, err := base64.StdEncoding.DecodeString(string(intermediate))
				if err != nil {
					continue
				}

				envSig.Intermediates = append(envSig.Intermediates, decoded)
			}
		}

		env.Signatures = append(env.Signatures, envSig)
	}

	return env, nil
}
