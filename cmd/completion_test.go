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
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CompletionCmd(t *testing.T) {
	cmd := CompletionCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "completion [bash|zsh|fish|powershell]", cmd.Use)
	assert.Equal(t, true, cmd.DisableFlagsInUseLine)
	assert.Equal(t, true, cmd.DisableAutoGenTag)
	
	// Test that ValidArgs contains the expected values
	expectedValidArgs := []string{"bash", "zsh", "fish", "powershell"}
	assert.Equal(t, expectedValidArgs, cmd.ValidArgs)
	
	// Test that Args validation works as expected
	assert.NoError(t, cmd.Args(cmd, []string{"bash"}))
	assert.NoError(t, cmd.Args(cmd, []string{"zsh"}))
	assert.NoError(t, cmd.Args(cmd, []string{"fish"}))
	assert.NoError(t, cmd.Args(cmd, []string{"powershell"}))
	assert.Error(t, cmd.Args(cmd, []string{"invalid"}))
	assert.Error(t, cmd.Args(cmd, []string{}))
	assert.Error(t, cmd.Args(cmd, []string{"bash", "extra"}))
}

func Test_CompletionCmd_Run(t *testing.T) {
	tests := []struct {
		name     string
		shell    string
		contains string // just check for a common string that should be in all completions
	}{
		{
			name:     "bash",
			shell:    "bash",
			contains: "# bash completion",
		},
		{
			name:     "zsh",
			shell:    "zsh",
			contains: "#compdef",
		},
		{
			name:     "fish",
			shell:    "fish",
			contains: "# fish completion",
		},
		{
			name:     "powershell",
			shell:    "powershell",
			contains: "Register-ArgumentCompleter",
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a root command for completions to work with
			rootCmd := &cobra.Command{Use: "witness"}
			
			// Add the completion command to the root
			completionCmd := CompletionCmd()
			rootCmd.AddCommand(completionCmd)
			
			// Redirect stdout to capture output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			
			// Execute the completion command directly
			completionCmd.Run(completionCmd, []string{tc.shell})
			
			// Restore stdout
			w.Close()
			os.Stdout = oldStdout
			
			// Read the captured output
			var buf bytes.Buffer
			_, err := io.Copy(&buf, r)
			require.NoError(t, err)
			
			// Check the output contains the expected content
			assert.Contains(t, buf.String(), tc.contains)
		})
	}
}