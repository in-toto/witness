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
	"os"
	"path/filepath"
	"testing"
)

// Test for the logger SetLevel function which is called by preRoot
func TestPreRootLogLevel(t *testing.T) {
	// Create our test logger
	logger := newLogger()
	
	// Test various log levels
	logLevels := []string{"debug", "info", "warn", "error"}
	
	for _, level := range logLevels {
		t.Run("Log level "+level, func(t *testing.T) {
			// Test the logger's SetLevel function
			err := logger.SetLevel(level)
			if err != nil {
				t.Errorf("Failed to set log level %s: %v", level, err)
			}
		})
	}
	
	// Test invalid log level
	t.Run("Invalid log level", func(t *testing.T) {
		err := logger.SetLevel("invalid")
		if err == nil {
			t.Error("Expected error for invalid log level, got nil")
		}
	})
}

// Test loadOutfile function which is used in several commands
func TestLoadOutfileExtended(t *testing.T) {
	// Test with valid file path
	t.Run("Valid outfile path", func(t *testing.T) {
		// Get a temporary file path
		tempDir := t.TempDir()
		outPath := filepath.Join(tempDir, "output.txt")
		
		// Test loadOutfile
		file, err := loadOutfile(outPath)
		if err != nil {
			t.Fatalf("loadOutfile(%s) error: %v", outPath, err)
		}
		defer func() { _ = file.Close() }()
		
		// Check file is created and writable
		_, err = file.Write([]byte("test data"))
		if err != nil {
			t.Errorf("Failed to write to output file: %v", err)
		}
		
		// Verify file exists
		_, err = os.Stat(outPath)
		if err != nil {
			t.Errorf("File does not exist after loadOutfile: %v", err)
		}
	})
	
	// Test with empty path (should return stdout)
	t.Run("Stdout path", func(t *testing.T) {
		file, err := loadOutfile("")
		if err != nil {
			t.Fatalf("loadOutfile(\"\") error: %v", err)
		}
		
		// Check file is stdout
		if file != os.Stdout {
			t.Errorf("Expected os.Stdout, got something else")
		}
	})
	
	// Test with path to non-existent directory
	t.Run("Invalid directory", func(t *testing.T) {
		badPath := "/nonexistent/directory/output.txt"
		
		// This should fail because the directory doesn't exist
		_, err := loadOutfile(badPath)
		if err == nil {
			t.Error("Expected error for non-existent directory, got nil")
		}
	})
}