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

package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Enhanced test for Execute function covering error paths
func TestExecuteFunction(t *testing.T) {
	// Save original os.Exit, os.Args, and restore them after test
	origExit := osExit
	oldArgs := os.Args
	defer func() { 
		osExit = origExit 
		os.Args = oldArgs
	}()
	
	// Create variables to capture exit code
	var exitCode int
	
	// Mock os.Exit to avoid actual termination
	osExit = func(code int) {
		exitCode = code
		// Don't actually exit the test
	}
	
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{
			name:     "help command",
			args:     []string{"witness", "--help"},
			wantCode: 0, // Success
		},
		{
			name:     "invalid command",
			args:     []string{"witness", "invalid-command"},
			wantCode: 1, // Error
		},
		{
			name:     "version command",
			args:     []string{"witness", "version"},
			wantCode: 0, // Success
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset exit code
			exitCode = 0
			
			// Override os.Args temporarily
			os.Args = tt.args
			
			// Execute should run without actually exiting
			Execute()
			
			// Check exit code
			assert.Equal(t, tt.wantCode, exitCode, "Execute with %v should result in exit code %d", tt.args, tt.wantCode)
		})
	}
}

// Test for New command structure
func TestNewCommand(t *testing.T) {
	cmd := New()
	require.NotNil(t, cmd, "Root command should be created")
	assert.Equal(t, "witness", cmd.Use, "Root command should have correct name")
	assert.NotEmpty(t, cmd.Short, "Root command should have a short description")
	assert.True(t, cmd.SilenceErrors, "SilenceErrors should be true")
}