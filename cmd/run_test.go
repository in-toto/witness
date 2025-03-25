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

package cmd

import (
	"errors"
	"fmt"
	"testing"

	werrors "github.com/in-toto/witness/internal/errors"
	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/assert"
)

// TestRunAttestorFailure tests the new error type detection logic
func TestRunAttestorFailure(t *testing.T) {
	err1 := fmt.Errorf("attestor did not work")
	err2 := fmt.Errorf("failed to save artifact")

	tests := []struct {
		name        string
		err         error
		errType     string
		expectedErr error
	}{
		{
			name:        "attestor error is AttestorError",
			err:         werrors.NewAttestorError("test-attestor", err1),
			errType:     "attestor",
			expectedErr: err1,
		},
		{
			name:        "infrastructure error is InfrastructureError",
			err:         werrors.NewInfrastructureError("test-operation", err2),
			errType:     "infra",
			expectedErr: err2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test error type detection
			if tt.errType == "attestor" {
				assert.True(t, isAttestorError(tt.err), "Error should be detected as attestor error")
				assert.True(t, werrors.IsAttestorError(tt.err), "Error should be detected as attestor error")
			} else {
				assert.False(t, isAttestorError(tt.err), "Error should not be detected as attestor error")
				assert.True(t, werrors.IsInfrastructureError(tt.err), "Error should be detected as infrastructure error")
			}

			// Test error unwrapping
			assert.True(t, errors.Is(tt.err, tt.expectedErr), "Error should unwrap to the original error")
		})
	}
}

// TestErrorHandling tests the error handling infrastructure
func TestErrorHandling(t *testing.T) {
	// Test scenarios for handleInfraError
	t.Run("handleInfraError", func(t *testing.T) {
		origErr := fmt.Errorf("test error")
		ro := options.RunOptions{
			ContinueOnInfraError: true,
		}

		shouldContinue, resultErr := handleInfraError(ro, origErr, "test operation", true)
		assert.True(t, shouldContinue, "Should continue when flag is set and command succeeded")
		assert.NotNil(t, resultErr, "Result error should not be nil")
		assert.True(t, werrors.IsInfrastructureError(resultErr), "Result should be an infrastructure error")

		// Test when command failed
		shouldContinue, resultErr = handleInfraError(ro, origErr, "test operation", false)
		assert.False(t, shouldContinue, "Should not continue when command failed")
		assert.Nil(t, resultErr, "Result error should be nil when not continuing")

		// Test when flag is not set
		ro.ContinueOnInfraError = false
		shouldContinue, resultErr = handleInfraError(ro, origErr, "test operation", true)
		assert.False(t, shouldContinue, "Should not continue when flag is not set")
		assert.Nil(t, resultErr, "Result error should be nil when not continuing")
	})

	// Test scenarios for handleErrorWithContinueFlags with attestor error
	t.Run("handleErrorWithContinueFlags-attestor", func(t *testing.T) {
		attestorErr := werrors.NewAttestorError("test-attestor", fmt.Errorf("attestor error"))
		ro := options.RunOptions{
			ContinueOnAttestorError: true,
		}

		shouldContinue, infraErr, attErr := handleErrorWithContinueFlags(ro, attestorErr, true)
		assert.True(t, shouldContinue, "Should continue when attestor flag is set and command succeeded")
		assert.Nil(t, infraErr, "Infra error should be nil")
		assert.NotNil(t, attErr, "Attestor error should not be nil")
		assert.True(t, werrors.IsAttestorError(attErr), "Result should be an attestor error")

		// Test when command failed
		shouldContinue, infraErr, attErr = handleErrorWithContinueFlags(ro, attestorErr, false)
		assert.False(t, shouldContinue, "Should not continue when command failed")
		assert.Nil(t, infraErr, "Infra error should be nil")
		assert.Nil(t, attErr, "Attestor error should be nil")

		// Test with all errors flag
		ro.ContinueOnAttestorError = false
		ro.ContinueOnAllErrors = true
		shouldContinue, infraErr, attErr = handleErrorWithContinueFlags(ro, attestorErr, true)
		assert.True(t, shouldContinue, "Should continue when all errors flag is set")
		assert.Nil(t, infraErr, "Infra error should be nil")
		assert.NotNil(t, attErr, "Attestor error should not be nil")
	})

	// Test scenarios for handleErrorWithContinueFlags with infra error
	t.Run("handleErrorWithContinueFlags-infra", func(t *testing.T) {
		infraError := werrors.NewInfrastructureError("test-operation", fmt.Errorf("infra error"))
		ro := options.RunOptions{
			ContinueOnInfraError: true,
		}

		shouldContinue, infraErr, attErr := handleErrorWithContinueFlags(ro, infraError, true)
		assert.True(t, shouldContinue, "Should continue when infra flag is set and command succeeded")
		assert.NotNil(t, infraErr, "Infra error should not be nil")
		assert.Nil(t, attErr, "Attestor error should be nil")
		assert.True(t, werrors.IsInfrastructureError(infraErr), "Result should be an infra error")

		// Test with all errors flag
		ro.ContinueOnInfraError = false
		ro.ContinueOnAllErrors = true
		shouldContinue, infraErr, attErr = handleErrorWithContinueFlags(ro, infraError, true)
		assert.True(t, shouldContinue, "Should continue when all errors flag is set")
		assert.NotNil(t, infraErr, "Infra error should not be nil")
		assert.Nil(t, attErr, "Attestor error should be nil")
	})
}