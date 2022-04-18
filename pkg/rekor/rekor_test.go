// Copyright 2022 The Witness Contributors
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sigstore/rekor/pkg/client"
	"github.com/stretchr/testify/require"
	witness "github.com/testifysec/witness/pkg"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
)

type testresp struct {
	method   string
	path     string
	response string
	code     int
}

func GetTestResponses() []testresp {
	return []testresp{
		{"POST", "/api/v1/log/entries", testResponse1, http.StatusCreated},
		{"GET", "/api/v1/log/entries/4f148820e7d6cc42d32d309e529a97f52f17fa8618ddfb56848f40d6ec432006", test126, http.StatusOK},
		{"GET", "/api/v1/log/entries/90d8a2b6d99025ae1a4c7263ea8e6d69d71468ed5065d6ab756a59ada2020fae", test127, http.StatusOK},
		{"GET", "/api/v1/log/entries/4518d165be23ceef26c8db321b018ec0333106f729f0394c3205c4e18066937d", test128, http.StatusOK},
		{"GET", "/api/v1/log/entries/ee8e29ed69d0c3f827e1c5019336a5f89aecd7a9a9975ba3949a7356377d8778", test129, http.StatusOK},
		{"GET", "/api/v1/log/entries/8b65813480766f304952bb27510eefae2c44cef3f7a471ddde00b3d1e408c115", test130, http.StatusOK},
		{"GET", "/api/v1/log/entries/47b50a34ea17fe5c0698794e5b86896680db129b110ccb536ab6640667bf6389", test131, http.StatusOK},
		{"POST", "/api/v1/index/retrieve", indexres, http.StatusOK},
	}
}

func initTestServer(t *testing.T, testresponses []testresp) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error

		for _, resp := range testresponses {
			if r.URL.Path == resp.path && r.Method == resp.method {
				switch r.Method {
				case "POST":
					w.Header().Set("Content-Type", "application/json;q=1")
					w.WriteHeader(resp.code)
					_, err = w.Write([]byte(resp.response))
				case "GET":
					w.Header().Set("Content-Type", "application/json;q=1")
					w.WriteHeader(resp.code)
					_, err = w.Write([]byte(resp.response))
				default:
					t.Fatalf("unexpected method %s", r.Method)

				}

				require.NoError(t, err)
			}
		}
	}))
}

func getTestRekorClient(t *testing.T) *wrappedRekorClient {
	t.Helper()

	s := initTestServer(t, GetTestResponses())
	client, err := client.GetRekorClient(s.URL)
	if err != nil {
		return nil
	}

	return &wrappedRekorClient{
		Rekor:          client,
		url:            s.URL,
		searchedHashes: make(map[string]bool),
		searchedIndex:  make(map[string]bool),
	}
}

func Test_wrappedRekorClient_StoreArtifact(t *testing.T) {
	workingDir := t.TempDir()

	rc := getTestRekorClient(t)

	key, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)

	signer, err := cryptoutil.NewSigner(key)
	require.NoError(t, err)

	args := []string{
		"bash",
		"-c",
		"echo 'test' > test.txt",
	}

	result, err := witness.Run(
		"test01",
		signer,
		witness.RunWithCommand(args),
		witness.RunWithAttestors([]string{}),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(workingDir)),
	)

	require.NoError(t, err)

	signedBytes, err := json.MarshalIndent(result.SignedEnvelope, "", "  ")
	fmt.Println(string(signedBytes))
	require.NoError(t, err)

	require.NoError(t, err)

	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := verifier.Bytes()
	require.NoError(t, err)

	entry, err := rc.StoreArtifact(signedBytes, pub)

	require.NoError(t, err)
	require.NotNil(t, entry)
}

func Test_FindEntriesBySubject(t *testing.T) {
	rc := getTestRekorClient(t)

	ds := cryptoutil.DigestSet{}

	ds[crypto.SHA256] = filehash

	entries, err := rc.FindEntriesBySubject(ds)
	require.Len(t, entries, 6)
	require.NoError(t, err)
	require.NotNil(t, entries)
}

func Test_FindEvidence(t *testing.T) {
	rc := getTestRekorClient(t)

	ds := cryptoutil.DigestSet{}

	ds[crypto.SHA256] = filehash

	policyEnvelope := dsse.Envelope{}

	err := json.Unmarshal([]byte(testpolicy), &policyEnvelope)
	require.NoError(t, err)

	publicKey := []byte(testpolicykey)
	reader := bytes.NewReader(publicKey)

	verifier, err := cryptoutil.NewVerifierFromReader(reader)
	require.NoError(t, err)

	entry, err := rc.FindEvidence([]cryptoutil.DigestSet{ds}, policyEnvelope, []cryptoutil.Verifier{verifier}, []witness.CollectionEnvelope{}, 2)
	for _, e := range entry {
		fmt.Println(e.Reference)
	}

	require.NoError(t, err)
	require.NotNil(t, entry)
}
