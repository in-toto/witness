// Copyright 2025 The Witness Contributors
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

package archivista

import (
	"context"
	"testing"

	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Create a mock archivista client for testing
type mockArchivistaClient struct {
	downloadFunc    func(ctx context.Context, gitoid string) (dsse.Envelope, error)
	storeFunc       func(ctx context.Context, env dsse.Envelope) (string, error)
	searchGitoidFunc func(ctx context.Context, vars archivista.SearchGitoidVariables) ([]string, error)
}

func (m *mockArchivistaClient) Download(ctx context.Context, gitoid string) (dsse.Envelope, error) {
	if m.downloadFunc != nil {
		return m.downloadFunc(ctx, gitoid)
	}
	return dsse.Envelope{}, nil
}

func (m *mockArchivistaClient) Store(ctx context.Context, env dsse.Envelope) (string, error) {
	if m.storeFunc != nil {
		return m.storeFunc(ctx, env)
	}
	return "", nil
}

func (m *mockArchivistaClient) SearchGitoids(ctx context.Context, vars archivista.SearchGitoidVariables) ([]string, error) {
	if m.searchGitoidFunc != nil {
		return m.searchGitoidFunc(ctx, vars)
	}
	return nil, nil
}

// Test NewArchivistaClient function
func TestNewArchivistaClient(t *testing.T) {
	t.Run("with nil client", func(t *testing.T) {
		client := NewArchivistaClient("https://test.com", nil)
		assert.Nil(t, client, "Should return nil when client is nil")
	})

	t.Run("with valid client", func(t *testing.T) {
		client := NewArchivistaClient("https://test.com", &archivista.Client{})
		assert.NotNil(t, client, "Should create a client when archivista client is provided")
		assert.IsType(t, &aClient{}, client, "Should return an aClient instance")
	})
}

// Test Download method
func TestAClient_Download(t *testing.T) {
	expectedEnvelope := dsse.Envelope{
		PayloadType: "test-type",
		Payload:     []byte("test-payload"),
	}

	mock := &mockArchivistaClient{
		downloadFunc: func(ctx context.Context, gitoid string) (dsse.Envelope, error) {
			assert.Equal(t, "test-gitoid", gitoid, "Should pass gitoid to underlying client")
			return expectedEnvelope, nil
		},
	}

	// Create test client
	client := &aClient{
		url:    "https://test.com",
		client: mock,
	}

	// Test the Download method
	envelope, err := client.Download(context.Background(), "test-gitoid")
	require.NoError(t, err)
	assert.Equal(t, expectedEnvelope, envelope, "Should return envelope from underlying client")
}

// Test Store method
func TestAClient_Store(t *testing.T) {
	testEnvelope := dsse.Envelope{
		PayloadType: "test-type",
		Payload:     []byte("test-payload"),
	}

	expectedGitoid := "test-gitoid-result"

	mock := &mockArchivistaClient{
		storeFunc: func(ctx context.Context, env dsse.Envelope) (string, error) {
			assert.Equal(t, testEnvelope, env, "Should pass envelope to underlying client")
			return expectedGitoid, nil
		},
	}

	// Create test client
	client := &aClient{
		url:    "https://test.com",
		client: mock,
	}

	// Test the Store method
	gitoid, err := client.Store(context.Background(), testEnvelope)
	require.NoError(t, err)
	assert.Equal(t, expectedGitoid, gitoid, "Should return gitoid from underlying client")
}

// Test SearchGitoids method
func TestAClient_SearchGitoids(t *testing.T) {
	expectedGitoids := []string{"gitoid1", "gitoid2"}

	mock := &mockArchivistaClient{
		searchGitoidFunc: func(ctx context.Context, vars archivista.SearchGitoidVariables) ([]string, error) {
			// We don't need to validate the specific vars structure
			return expectedGitoids, nil
		},
	}

	// Create test client
	client := &aClient{
		url:    "https://test.com",
		client: mock,
	}

	// Test the SearchGitoids method
	vars := archivista.SearchGitoidVariables{}
	gitoids, err := client.SearchGitoids(context.Background(), vars)
	require.NoError(t, err)
	assert.Equal(t, expectedGitoids, gitoids, "Should return gitoids from underlying client")
}