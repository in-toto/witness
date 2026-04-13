// Copyright 2024 The Witness Contributors
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

package cmd

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/require"
)

func TestAttachAttestation(t *testing.T) {
	// Setup in-memory registry
	s := httptest.NewServer(registry.New())
	defer s.Close()

	ctx := context.Background()

	// Push a random image to the registry to test against
	img, err := random.Image(1024, 1)
	require.NoError(t, err)
	imgDigest, err := img.Digest()
	require.NoError(t, err)

	refStr := s.URL[7:] + "/test-image:latest" // strip http://
	ref, err := name.ParseReference(refStr)
	require.NoError(t, err)

	err = remote.Write(ref, img, remote.WithContext(ctx))
	require.NoError(t, err)

	// Create temporary directory for our test attestations
	tempDir := t.TempDir()

	tests := []struct {
		name             string
		payloadType      string
		noSignatures     bool
		subjectDigest    string
		skipVerification bool
		expectErr        string
	}{
		{
			name:          "matching subject digest",
			payloadType:   "application/vnd.in-toto+json",
			subjectDigest: imgDigest.Hex,
		},
		{
			name:             "mismatching subject digest with skip verification",
			payloadType:      "application/vnd.in-toto+json",
			subjectDigest:    "wrongdigest",
			skipVerification: true,
		},
		{
			name:          "mismatching subject digest fails",
			payloadType:   "application/vnd.in-toto+json",
			subjectDigest: "wrongdigest",
			expectErr:     "subject digest mismatch",
		},
		{
			name:          "unsupported payload type",
			payloadType:   "application/vnd.other",
			subjectDigest: imgDigest.Hex,
			expectErr:     "unsupported payloadType",
		},
		{
			name:          "missing signatures",
			payloadType:   "application/vnd.in-toto+json",
			subjectDigest: imgDigest.Hex,
			noSignatures:  true,
			expectErr:     "has no signatures",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stmt IntotoStatement
			stmt.Type = "https://in-toto.io/Statement/v1"

			stmt.Subject = append(stmt.Subject, struct {
				Name   string            `json:"name"`
				Digest map[string]string `json:"digest"`
			}{
				Name: "test-artifact",
				Digest: map[string]string{
					"sha256": tc.subjectDigest, // hex without sha256: prepended
				},
			})

			stmtBytes, err := json.Marshal(stmt)
			require.NoError(t, err)

			env := dsse.Envelope{
				PayloadType: tc.payloadType,
				Payload:     stmtBytes,
			}
			if !tc.noSignatures {
				env.Signatures = append(env.Signatures, dsse.Signature{
					Signature: []byte("dummy-sig"),
					KeyID:     "dummy-key",
				})
			}

			envBytes, err := json.Marshal(env)
			require.NoError(t, err)

			attestPath := filepath.Join(tempDir, tc.name+".json")
			err = os.WriteFile(attestPath, envBytes, 0644)
			require.NoError(t, err)

			ao := options.AttachOptions{
				ImageURI:         refStr,
				SkipVerification: tc.skipVerification,
			}

			err = runAttachAttestation(ctx, ao, []string{attestPath})
			if tc.expectErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
