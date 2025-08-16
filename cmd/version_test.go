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
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCmd(t *testing.T) {
	cmd := VersionCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "version", cmd.Use)
	assert.Equal(t, true, cmd.SilenceErrors)
	assert.Equal(t, true, cmd.SilenceUsage)
	assert.Equal(t, true, cmd.DisableAutoGenTag)

	// Test the command execution and output
	originalVersion := Version
	defer func() { Version = originalVersion }()

	// Redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Execute the command
	cmd.Run(&cobra.Command{}, []string{})

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	require.NoError(t, err)

	// Verify output
	assert.Equal(t, "witness dev\n", buf.String())
}
