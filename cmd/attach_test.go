// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"os"
	"testing"

	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/oci"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// todo: in-memory registry test (httptest + ggcr options)
func createTempFile(t *testing.T, envelope ssldsse.Envelope) string {
	tmpFile, err := os.CreateTemp("", "dsse-*.json")
	require.NoError(t, err)
	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Errorf("failed to close tmpFile: %v", err)
		}
	}()

	encoder := json.NewEncoder(tmpFile)
	err = encoder.Encode(envelope)
	require.NoError(t, err)

	return tmpFile.Name()
}

func TestValidateEnvelopePayloadType(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		expectError bool
	}{
		{
			name:        "valid intoto payload type",
			payloadType: types.IntotoPayloadType,
			expectError: false,
		},
		{
			name:        "invalid payload type",
			payloadType: "invalid/type",
			expectError: true,
		},
		{
			name:        "empty payload type",
			payloadType: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := ssldsse.Envelope{
				PayloadType: tt.payloadType,
				Payload:     "test-payload",
				Signatures: []ssldsse.Signature{
					{KeyID: "test", Sig: "test"},
				},
			}

			tmpFile := createTempFile(t, envelope)
			defer func() {
				if err := os.Remove(tmpFile); err != nil {
					log.Errorf("failed to remove tmpFile: %v", err)
				}
			}()

			ctx := context.Background()
			regOpts := oci.RegistryOptions{}
			err := AttestationCmd(ctx, regOpts, []string{tmpFile}, "gcr.io/test/image@sha256:d131624e6f5d8695e9aea7a0439f7bac0fcc50051282e0c3d4d627cab8845ba5")

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid payloadType")
			}
		})
	}
}

func TestValidateEnvelopeSignatures(t *testing.T) {
	tests := []struct {
		name        string
		signatures  []ssldsse.Signature
		expectError bool
	}{
		{
			name: "valid signatures",
			signatures: []ssldsse.Signature{
				{KeyID: "test", Sig: "test"},
			},
			expectError: false,
		},
		{
			name:        "empty signatures",
			signatures:  []ssldsse.Signature{},
			expectError: true,
		},
		{
			name:        "nil signatures",
			signatures:  nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := ssldsse.Envelope{
				PayloadType: types.IntotoPayloadType,
				Payload:     "test-payload",
				Signatures:  tt.signatures,
			}

			tmpFile := createTempFile(t, envelope)
			defer func() {
				if err := os.Remove(tmpFile); err != nil {
					log.Errorf("failed to remove tmpFile: %v", err)
				}
			}()

			ctx := context.Background()
			regOpts := oci.RegistryOptions{}
			err := AttestationCmd(ctx, regOpts, []string{tmpFile}, "gcr.io/test/image@sha256:d131624e6f5d8695e9aea7a0439f7bac0fcc50051282e0c3d4d627cab8845ba5")

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "could not attach attestation without having signatures")
			}
		})
	}
}
