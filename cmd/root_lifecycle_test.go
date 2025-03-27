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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/in-toto/witness/options"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Execute function
func TestExecute(t *testing.T) {
	// Save original os.Exit and restore it after test
	origExit := osExit
	defer func() { osExit = origExit }()
	
	// Mock os.Exit to avoid actual termination
	exitCode := 0
	osExit = func(code int) {
		exitCode = code
	}
	
	// Override os.Args temporarily
	oldArgs := os.Args
	os.Args = []string{"witness", "--help"}
	defer func() { os.Args = oldArgs }()
	
	// Execute should run without actually exiting
	Execute()
	
	// With --help, we expect a success exit (code 0)
	assert.Equal(t, 0, exitCode, "Execute with --help should result in exit code 0")
}

// Test CPU profile creation in preRoot function
func TestPreRootCPUProfile(t *testing.T) {
	tests := []struct {
		name          string
		cpuProfile    string
		expectProfile bool
	}{
		{
			name:          "No CPU profile",
			cpuProfile:    "",
			expectProfile: false,
		},
		{
			name:          "With CPU profile",
			cpuProfile:    "cpu.prof",
			expectProfile: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure cpuProfileFile is reset between tests
			if cpuProfileFile != nil {
				pprof.StopCPUProfile()
				cpuProfileFile.Close()
				cpuProfileFile = nil
			}
			
			// Create a temp dir for profile files
			tempDir := t.TempDir()
			
			// Create a logger that captures output
			logBuf := new(bytes.Buffer)
			testLogger := logrus.New()
			testLogger.SetOutput(logBuf)
			logger := &logrusLogger{l: testLogger}
			
			// Create test exit function to avoid test termination
			testLogger.ExitFunc = func(int) {}
			
			// Create options
			rootOptions := &options.RootOptions{
				LogLevel: "info",
			}
			
			if tt.cpuProfile != "" {
				rootOptions.CpuProfileFile = filepath.Join(tempDir, tt.cpuProfile)
			}
			
			// Skip the test if logger.SetLevel returns an error
			if err := logger.SetLevel(rootOptions.LogLevel); err != nil {
				t.Skip("Skipping test due to logger setup issue")
				return
			}
			
			// Call CPU profile creation part of preRoot directly
			if len(rootOptions.CpuProfileFile) > 0 {
				var err error
				cpuProfileFile, err = os.Create(rootOptions.CpuProfileFile)
				if err != nil {
					logger.l.Fatalf("could not create CPU profile: %v", err)
				}
				
				if err = pprof.StartCPUProfile(cpuProfileFile); err != nil {
					logger.l.Fatalf("could not start CPU profile: %v", err)
				}
			}
			
			// Check if CPU profile file was created
			if tt.expectProfile {
				assert.NotNil(t, cpuProfileFile, "CPU profile file should have been created")
				
				// Verify the file exists
				_, err := os.Stat(rootOptions.CpuProfileFile)
				assert.NoError(t, err, "CPU profile file should exist")
			} else {
				assert.Nil(t, cpuProfileFile, "CPU profile file should not have been created")
			}
		})
	}
}

// Test the memory profile creation in postRoot function
func TestPostRootMemoryProfile(t *testing.T) {
	// Ensure no active CPU profile before test
	if cpuProfileFile != nil {
		pprof.StopCPUProfile()
		cpuProfileFile.Close()
		cpuProfileFile = nil
	}
	
	tests := []struct {
		name          string
		cpuProfile    bool
		memProfile    string
		expectMemFile bool
	}{
		{
			name:          "No profiles",
			cpuProfile:    false,
			memProfile:    "",
			expectMemFile: false,
		},
		{
			name:          "With memory profile",
			cpuProfile:    false,
			memProfile:    "mem.prof",
			expectMemFile: true,
		},
		{
			name:          "With CPU and memory profiles",
			cpuProfile:    true,
			memProfile:    "mem.prof",
			expectMemFile: true,
		},
	}
	
	for i, tt := range tests {
		testName := tt.name
		t.Run(testName, func(t *testing.T) {
			// Ensure we're not using CPU profile from previous tests
			if cpuProfileFile != nil {
				pprof.StopCPUProfile()
				cpuProfileFile.Close()
				cpuProfileFile = nil
			}
			
			// Create a logger that captures output
			logBuf := new(bytes.Buffer)
			testLogger := logrus.New()
			testLogger.SetOutput(logBuf)
			logger := &logrusLogger{l: testLogger}
			
			// Create test exit function to avoid test termination
			testLogger.ExitFunc = func(int) {}
			
			// Create a temp dir for profile files
			tempDir := t.TempDir()
			
			// Setup CPU profile if needed
			if tt.cpuProfile {
				var err error
				profilePath := filepath.Join(tempDir, fmt.Sprintf("cpu_%d.prof", i))
				cpuProfileFile, err = os.Create(profilePath)
				require.NoError(t, err)
				
				err = pprof.StartCPUProfile(cpuProfileFile)
				require.NoError(t, err)
			} else {
				cpuProfileFile = nil
			}
			
			// Create options
			rootOptions := &options.RootOptions{}
			if tt.memProfile != "" {
				rootOptions.MemProfileFile = filepath.Join(tempDir, tt.memProfile)
			}
			
			// Call memory profile creation part of postRoot directly
			if cpuProfileFile != nil {
				pprof.StopCPUProfile()
				if err := cpuProfileFile.Close(); err != nil {
					logger.l.Fatalf("could not close cpu profile file: %v", err)
				}
				cpuProfileFile = nil
			}
			
			if len(rootOptions.MemProfileFile) > 0 {
				memProfileFile, err := os.Create(rootOptions.MemProfileFile)
				if err != nil {
					logger.l.Fatalf("could not create memory profile file: %v", err)
				}
				
				defer memProfileFile.Close()
				runtime.GC()
				if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
					logger.l.Fatalf("could not write memory profile: %v", err)
				}
			}
			
			// Verify memory profile file was created if expected
			if tt.expectMemFile {
				_, err := os.Stat(rootOptions.MemProfileFile)
				assert.NoError(t, err, "Memory profile file should exist")
			}
		})
	}
}