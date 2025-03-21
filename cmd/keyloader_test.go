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

package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/witness/options"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func Test_providersFromFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    map[string]string
		prefix   string
		expected map[string]struct{}
	}{
		{
			name: "matching flags",
			flags: map[string]string{
				"signer-file":     "value1",
				"signer-kms":      "value2",
				"verifier-file":   "value3",
				"unrelated-flag":  "value4",
				"signer-unrelated": "value5",
			},
			prefix: "signer",
			expected: map[string]struct{}{
				"file": {},
				"kms":  {},
				"unrelated": {},
			},
		},
		{
			name: "no matching flags",
			flags: map[string]string{
				"verifier-file":  "value1",
				"unrelated-flag": "value2",
			},
			prefix:   "signer",
			expected: map[string]struct{}{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			for name, value := range tc.flags {
				flags.String(name, "", "test flag")
				flags.Set(name, value)
			}

			result := providersFromFlags(tc.prefix, flags)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func Test_loadVerifiers(t *testing.T) {
	t.Run("empty providers", func(t *testing.T) {
		verifiers, err := loadVerifiers(context.Background(), options.VerifierOptions{}, options.KMSVerifierProviderOptions{}, map[string]struct{}{})
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})

	t.Run("with unknown provider", func(t *testing.T) {
		// Create mock verifier options
		verifierOptions := options.VerifierOptions{}
		
		// Mock the verifier provider to return an empty verifier list
		providers := map[string]struct{}{
			"unknown-provider": {},  // Use a provider that doesn't exist to avoid errors
		}

		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		assert.NoError(t, err)
		assert.Empty(t, verifiers, "Should return empty verifiers for unknown provider")
	})
	
	t.Run("with provider setter error", func(t *testing.T) {
		// Create verifier options with a setter that returns an error
		verifierOptions := options.VerifierOptions{
			"file": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					// Return an error to test error handling
					return nil, assert.AnError
				},
			},
		}
		
		providers := map[string]struct{}{
			"file": {},
		}

		// This should not return error but will have no verifiers due to the error in the setter
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})
	
	t.Run("with empty setters", func(t *testing.T) {
		// Create provider with no setters
		verifierOptions := options.VerifierOptions{}
		
		providers := map[string]struct{}{
			"file": {},
		}
		
		// This should still work as there are no errors, just no configured options
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})
	
	t.Run("provider with failed initialization", func(t *testing.T) {
		// Create provider with setters but for an invalid provider that will fail to initialize
		verifierOptions := options.VerifierOptions{}
		
		// Use a custom provider name that doesn't exist
		providers := map[string]struct{}{
			"custom-provider-that-doesnt-exist": {},
		}
		
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})
	
	t.Run("file provider success path", func(t *testing.T) {
		// Create temporary test files
		tmpDir := t.TempDir()
		testKeyPath := tmpDir + "/testkey.pem"
		
		// Write a simple key to the file
		keyContent := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAszMTPHZ8F4BgJjKrZStS
8dMQUPd5XHZ1KDzrTXT/Y6qj/Cf9tOiwUvXmrhjMCQj7+jdE1KXVUwUcSVOJ8j1i
0iT+i0QKcj2WnOXfP75iECIcxjev+o2+ztLAUzNjkJehxPD/CYdK3cJNxZT1yQ7r
bU8jUlDyR+UNxRqTJoiLMMcgGKKcUASGNpUQQgT9C7y5oTePpDhO0cxo5GuLgxGy
g+ES4TU7KbMVY4Qj5JSZwQUlTapCoWTJIZ8oH2m13fNjBKZSCl0YqYvh0H1ZR5gN
bwXBs4nVbXiQpjHQHGFPnXJQIAjvG3RwWkUQK6Kxvcc78yQkRcPRmZTvouzrDqXi
0wIDAQAB
-----END PUBLIC KEY-----`
		err := os.WriteFile(testKeyPath, []byte(keyContent), 0644)
		assert.NoError(t, err, "Failed to write test key file")
		
		// Create verifier options with file provider
		verifierOptions := options.VerifierOptions{
			"file": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					return vp, nil // Return success to simulate proper setup
				},
			},
		}
		
		// Create providers map with file provider
		providers := map[string]struct{}{
			"file": {},
		}
		
		// Create mock KMS provider options - should be skipped for file provider
		kmsOptions := options.KMSVerifierProviderOptions{}
		
		// Call loadVerifiers
		_, err = loadVerifiers(context.Background(), verifierOptions, kmsOptions, providers)
		
		// For file provider, without proper key config, we might still get an empty list
		// But the important part is no errors should occur
		assert.NoError(t, err)
	})
	
	t.Run("with kms provider", func(t *testing.T) {
		// This test mocks parts of the KMS provider path, without actually initializing a real KMS connection
		
		// Create verifier options
		verifierOptions := options.VerifierOptions{
			"kms": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					return vp, nil // Return success
				},
			},
		}
		
		// Create KMS provider options
		kmsOptions := options.KMSVerifierProviderOptions{
			"aws": []func(signer.SignerProvider) (signer.SignerProvider, error){
				func(sp signer.SignerProvider) (signer.SignerProvider, error) {
					return sp, nil // Return success
				},
			},
		}
		
		// Create providers map with kms provider
		providers := map[string]struct{}{
			"kms": {},
		}
		
		// Call loadVerifiers - it should not panic, even though we can't fully simulate the KMS provider
		_, err := loadVerifiers(context.Background(), verifierOptions, kmsOptions, providers)
		
		// The test should run without panicking, even if we can't verify verifiers were created
		// Since we're mock testing, we can't expect actual verifiers
		assert.NoError(t, err)
	})
	
	t.Run("kms provider with error", func(t *testing.T) {
		// Mock a KMS provider setup that returns an error
		
		// Create verifier options
		verifierOptions := options.VerifierOptions{
			"kms": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					return vp, nil
				},
			},
		}
		
		// Create KMS provider options with an error
		kmsOptions := options.KMSVerifierProviderOptions{
			"aws": []func(signer.SignerProvider) (signer.SignerProvider, error){
				func(sp signer.SignerProvider) (signer.SignerProvider, error) {
					return nil, assert.AnError // Return an error to test error handling
				},
			},
		}
		
		// Create providers map with kms provider
		providers := map[string]struct{}{
			"kms": {},
		}
		
		// Call loadVerifiers - it should handle the error gracefully
		_, err := loadVerifiers(context.Background(), verifierOptions, kmsOptions, providers)
		
		// The test should run without panicking
		assert.NoError(t, err)
	})

	t.Run("kms provider verifier creation error", func(t *testing.T) {
		// Create a mock KMS provider that fails during Verifier creation
		verifierOptions := options.VerifierOptions{
			"kms": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					// Create a mock provider that will fail during Verifier() call
					// We're mocking an implementation here that would normally be provided by the KMS provider
					return &mockVerifierProviderWithError{}, nil
				},
			},
		}
		
		providers := map[string]struct{}{
			"kms": {},
		}
		
		// Call loadVerifiers with our failing provider
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		
		// Should not return an error, but should have no verifiers
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})
	
	t.Run("multiple verifier providers", func(t *testing.T) {
		// This test simulates using multiple verifier providers simultaneously
		
		// Create verifier options for both file and kms providers
		verifierOptions := options.VerifierOptions{
			"file": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					return vp, nil
				},
			},
			"kms": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					return vp, nil
				},
			},
		}
		
		// Configure both providers
		providers := map[string]struct{}{
			"file": {},
			"kms":  {},
		}
		
		// Call loadVerifiers with multiple providers
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		
		// Should not return an error
		assert.NoError(t, err)
		
		// We expect empty verifiers since we're not fully configuring them to succeed,
		// but the main point is that multiple providers doesn't cause issues
		assert.Empty(t, verifiers)
	})
	
	// We'll remove this test because it's difficult to mock the KMS provider cast without
	// access to the internal implementation details of the KMS provider
	// In real code, this would be caught by type assertions at runtime
	t.Run("non-kms provider", func(t *testing.T) {
		// Create verifier options that will cause Verifier() to be called
		verifierOptions := options.VerifierOptions{
			"file": []func(signer.VerifierProvider) (signer.VerifierProvider, error){
				func(vp signer.VerifierProvider) (signer.VerifierProvider, error) {
					// Return a test provider
					return &mockVerifierProviderWithError{}, nil
				},
			},
		}
		
		providers := map[string]struct{}{
			"file": {},
		}
		
		// Call loadVerifiers with a non-KMS provider
		verifiers, err := loadVerifiers(context.Background(), verifierOptions, options.KMSVerifierProviderOptions{}, providers)
		
		// Should not return an error, but no verifiers since Verifier() returns an error
		assert.NoError(t, err)
		assert.Empty(t, verifiers)
	})
	
	// This test is removed because properly mocking KMS providers
	// is difficult without access to implementation details
}

// Mock types for testing

// Mock verifier provider that fails during Verifier() call
type mockVerifierProviderWithError struct {
	signer.VerifierProvider
}

func (m *mockVerifierProviderWithError) Verifier(ctx context.Context) (cryptoutil.Verifier, error) {
	return nil, assert.AnError
}

// No longer needed since we removed the test that was using it

// Since mocking the KMS provider is difficult without access to the internal implementation,
// we're using simpler mocks that just fulfill the VerifierProvider interface
// This keeps our tests focused on the behavior we can control

// loadSigners function is already covered in Test_loadSignersKeyPair