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

package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAttestorError tests the AttestorError type functionality
func TestAttestorError(t *testing.T) {
	// Define test cases with different error scenarios
	testCases := []struct {
		name             string
		attestorName     string
		originalError    error
		expectedContains []string
		testWrapping     bool
	}{
		{
			name:             "basic error",
			attestorName:     "basic-attestor",
			originalError:    fmt.Errorf("something failed"),
			expectedContains: []string{"attestor error", "basic-attestor", "something failed"},
			testWrapping:     false,
		},
		{
			name:             "empty attestor name",
			attestorName:     "",
			originalError:    fmt.Errorf("attestor crashed"),
			expectedContains: []string{"attestor error", "attestor crashed"},
			testWrapping:     false,
		},
		{
			name:             "nil original error",
			attestorName:     "nil-error-attestor",
			originalError:    nil,
			expectedContains: []string{"attestor error", "nil-error-attestor", "<nil>"},
			testWrapping:     false,
		},
		{
			name:             "wrapped error test",
			attestorName:     "wrapped-attestor",
			originalError:    fmt.Errorf("root cause"),
			expectedContains: []string{"attestor error", "wrapped-attestor", "root cause"},
			testWrapping:     true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create attestor error
			attestorErr := NewAttestorError(tc.attestorName, tc.originalError)
			
			// Test error message format contains expected strings
			errMsg := attestorErr.Error()
			for _, expected := range tc.expectedContains {
				assert.Contains(t, errMsg, expected, "Error message should contain: %s", expected)
			}
			
			// Test Unwrap returns the original error
			unwrapped := attestorErr.Unwrap()
			assert.Equal(t, tc.originalError, unwrapped, "Unwrapped error should equal original error")
			
			// Test IsAttestorError detection works on the error
			assert.True(t, IsAttestorError(attestorErr), "IsAttestorError should return true for an AttestorError")
			
			// Test error wrapping if required
			if tc.testWrapping {
				// Test single level of wrapping
				singleWrapped := fmt.Errorf("level one: %w", attestorErr)
				assert.True(t, IsAttestorError(singleWrapped), 
					"IsAttestorError should detect AttestorError through one level of wrapping")
				
				// Test multiple levels of wrapping
				doubleWrapped := fmt.Errorf("level two: %w", singleWrapped)
				assert.True(t, IsAttestorError(doubleWrapped), 
					"IsAttestorError should detect AttestorError through multiple levels of wrapping")
				
				// Check errors.Is still works through wrapping
				if tc.originalError != nil {
					assert.True(t, errors.Is(doubleWrapped, tc.originalError), 
						"errors.Is should find original error through multiple wrappings")
				}
			}
		})
	}
	
	// Test that IsAttestorError returns false for non-attestor errors
	t.Run("detection of non-attestor errors", func(t *testing.T) {
		nonAttestorErr := fmt.Errorf("regular error")
		assert.False(t, IsAttestorError(nonAttestorErr), 
			"IsAttestorError should return false for regular errors")
		
		infraErr := NewInfrastructureError("test-operation", fmt.Errorf("infra error"))
		assert.False(t, IsAttestorError(infraErr), 
			"IsAttestorError should return false for InfrastructureError")
	})
}

// TestInfrastructureError tests the InfrastructureError type functionality
func TestInfrastructureError(t *testing.T) {
	// Define test cases with different error scenarios
	testCases := []struct {
		name             string
		operationName    string
		originalError    error
		expectedContains []string
		testWrapping     bool
	}{
		{
			name:             "basic error",
			operationName:    "basic-operation",
			originalError:    fmt.Errorf("something failed"),
			expectedContains: []string{"infrastructure error", "basic-operation", "something failed"},
			testWrapping:     false,
		},
		{
			name:             "empty operation name",
			operationName:    "",
			originalError:    fmt.Errorf("system crashed"),
			expectedContains: []string{"infrastructure error", "system crashed"},
			testWrapping:     false,
		},
		{
			name:             "nil original error",
			operationName:    "nil-error-operation",
			originalError:    nil,
			expectedContains: []string{"infrastructure error", "nil-error-operation", "<nil>"},
			testWrapping:     false,
		},
		{
			name:             "wrapped error test",
			operationName:    "wrapped-operation",
			originalError:    fmt.Errorf("root cause"),
			expectedContains: []string{"infrastructure error", "wrapped-operation", "root cause"},
			testWrapping:     true,
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create infrastructure error
			infraErr := NewInfrastructureError(tc.operationName, tc.originalError)
			
			// Test error message format contains expected strings
			errMsg := infraErr.Error()
			for _, expected := range tc.expectedContains {
				assert.Contains(t, errMsg, expected, "Error message should contain: %s", expected)
			}
			
			// Test Unwrap returns the original error
			unwrapped := infraErr.Unwrap()
			assert.Equal(t, tc.originalError, unwrapped, "Unwrapped error should equal original error")
			
			// Test IsInfrastructureError detection works on the error
			assert.True(t, IsInfrastructureError(infraErr), "IsInfrastructureError should return true for an InfrastructureError")
			
			// Test error wrapping if required
			if tc.testWrapping {
				// Test single level of wrapping
				singleWrapped := fmt.Errorf("level one: %w", infraErr)
				assert.True(t, IsInfrastructureError(singleWrapped), 
					"IsInfrastructureError should detect InfrastructureError through one level of wrapping")
				
				// Test multiple levels of wrapping
				doubleWrapped := fmt.Errorf("level two: %w", singleWrapped)
				assert.True(t, IsInfrastructureError(doubleWrapped), 
					"IsInfrastructureError should detect InfrastructureError through multiple levels of wrapping")
				
				// Check errors.Is still works through wrapping
				if tc.originalError != nil {
					assert.True(t, errors.Is(doubleWrapped, tc.originalError), 
						"errors.Is should find original error through multiple wrappings")
				}
			}
		})
	}
	
	// Test that IsInfrastructureError returns false for non-infrastructure errors
	t.Run("detection of non-infrastructure errors", func(t *testing.T) {
		nonInfraErr := fmt.Errorf("regular error")
		assert.False(t, IsInfrastructureError(nonInfraErr), 
			"IsInfrastructureError should return false for regular errors")
		
		attestorErr := NewAttestorError("test-attestor", fmt.Errorf("attestor error"))
		assert.False(t, IsInfrastructureError(attestorErr), 
			"IsInfrastructureError should return false for AttestorError")
	})
}

// TestErrorTypeDistinction tests that the error types are properly distinguished from each other
func TestErrorTypeDistinction(t *testing.T) {
	// Test cases covering different error types and complex wrapping scenarios
	testCases := []struct {
		name            string
		error           error
		isAttestor      bool
		isInfra         bool
		wrappingLevels  int // how many levels of wrapping to apply
		originalMessage string
	}{
		{
			name:            "simple attestor error",
			error:           NewAttestorError("test-attestor", fmt.Errorf("problem")),
			isAttestor:      true,
			isInfra:         false,
			wrappingLevels:  0,
			originalMessage: "problem",
		},
		{
			name:            "simple infrastructure error",
			error:           NewInfrastructureError("test-operation", fmt.Errorf("failure")),
			isAttestor:      false,
			isInfra:         true,
			wrappingLevels:  0,
			originalMessage: "failure",
		},
		// In Go's error wrapping, errors.As traverses the entire chain
		// which means embedded errors are detectable
		{
			name:            "deeply wrapped error",
			error:           fmt.Errorf("outer: %w", fmt.Errorf("middle: %w", NewAttestorError("inner", fmt.Errorf("core")))),
			isAttestor:      true,
			isInfra:         false,
			wrappingLevels:  2,
			originalMessage: "core",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test error type detection
			assert.Equal(t, tc.isAttestor, IsAttestorError(tc.error), 
				"IsAttestorError detection incorrect for %s", tc.name)
			assert.Equal(t, tc.isInfra, IsInfrastructureError(tc.error), 
				"IsInfrastructureError detection incorrect for %s", tc.name)
			
			// Test error unwrapping to find original message
			var err error = tc.error
			if tc.originalMessage != "" {
				// Apply additional wrapping as specified
				for i := 0; i < tc.wrappingLevels; i++ {
					err = fmt.Errorf("wrap%d: %w", i, err)
				}
				
				// Check if we can still detect the type
				assert.Equal(t, tc.isAttestor, IsAttestorError(err), 
					"IsAttestorError detection incorrect after wrapping for %s", tc.name)
				assert.Equal(t, tc.isInfra, IsInfrastructureError(err), 
					"IsInfrastructureError detection incorrect after wrapping for %s", tc.name)
				
				// Try to find the original message through the wrappings
				found := false
				for err != nil {
					if err.Error() == tc.originalMessage || (err.Error() != "" && 
						(len(err.Error()) >= len(tc.originalMessage) && 
						err.Error()[len(err.Error())-len(tc.originalMessage):] == tc.originalMessage)) {
						found = true
						break
					}
					unwrapErr := errors.Unwrap(err)
					if unwrapErr == nil {
						break
					}
					err = unwrapErr
				}
				
				if !found && tc.originalMessage != "" {
					assert.Fail(t, "Could not find original message in error chain", 
						"Original message '%s' not found in error chain for %s", 
						tc.originalMessage, tc.name)
				}
			}
		})
	}
}