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
	"path/filepath"
	"testing"

	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_initConfig(t *testing.T) {
	tests := []struct {
		name        string
		configPath  string
		configYaml  string
		createFile  bool
		forceFile   bool
		expectError bool
		cmdArgs     []string
	}{
		{
			name:        "Config file does not exist and not specified",
			configPath:  "notexists.yaml",
			createFile:  false,
			forceFile:   false,
			expectError: false,
			cmdArgs:     []string{"witness", "run"},
		},
		{
			name:        "Config file does not exist but specified",
			configPath:  "notexists.yaml",
			createFile:  false,
			forceFile:   true,
			expectError: true,
			cmdArgs:     []string{"witness", "run"},
		},
		{
			name:       "Valid config file with string values",
			configPath: "valid.yaml",
			configYaml: `
run:
  step: teststep
  outfile: outfile.json
`,
			createFile:  true,
			forceFile:   true,
			expectError: false,
			cmdArgs:     []string{"witness", "run"},
		},
		{
			name:       "Valid config file with string slices",
			configPath: "valid-slices.yaml",
			configYaml: `
verify:
  key: ["key1.pem", "key2.pem"]
`,
			createFile:  true,
			forceFile:   true,
			expectError: false,
			cmdArgs:     []string{"witness", "verify"},
		},
		{
			name:       "Invalid config file format",
			configPath: "invalid.yaml",
			configYaml: `
run:
  step: - teststep
    - invalid format
`,
			createFile:  true,
			forceFile:   true,
			expectError: true,
			cmdArgs:     []string{"witness", "run"},
		},
		{
			name:       "Command not matched in args",
			configPath: "valid.yaml",
			configYaml: `
run:
  step: teststep
`,
			createFile:  true,
			forceFile:   true,
			expectError: false,
			cmdArgs:     []string{"witness", "sign"}, // Different command than in config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, tt.configPath)

			// Create config file if needed
			if tt.createFile {
				err := os.WriteFile(configPath, []byte(tt.configYaml), 0644)
				require.NoError(t, err)
			}

			// Create command and options
			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.Flags().String("config", configPath, "")

			// Add test sub-commands
			runCmd := &cobra.Command{Use: "run"}
			runCmd.Flags().String("step", "", "Step name")
			runCmd.Flags().String("outfile", "", "Output file")
			rootCmd.AddCommand(runCmd)

			verifyCmd := &cobra.Command{Use: "verify"}
			verifyCmd.Flags().StringSlice("key", nil, "Key file paths")
			rootCmd.AddCommand(verifyCmd)

			signCmd := &cobra.Command{Use: "sign"}
			rootCmd.AddCommand(signCmd)

			if tt.forceFile {
				err := rootCmd.Flags().Set("config", configPath)
				require.NoError(t, err)
			}

			rootOptions := &options.RootOptions{
				Config: configPath,
			}

			// Save original args
			oldArgs := os.Args
			os.Args = tt.cmdArgs
			defer func() { os.Args = oldArgs }()

			// Reset viper
			viper.Reset()

			err := initConfig(rootCmd, rootOptions)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Check if flags were properly set from config for command in args
				if tt.createFile && !tt.expectError && len(tt.cmdArgs) > 1 {
					cmdName := tt.cmdArgs[1]
					for _, cmd := range rootCmd.Commands() {
						if cmd.Name() == cmdName {
							switch cmdName {
							case "run":
								stepNameFlag := cmd.Flags().Lookup("step")
								outfileFlag := cmd.Flags().Lookup("outfile")
								if tt.configYaml != "" {
									if tt.configPath == "valid.yaml" {
										assert.Equal(t, "teststep", stepNameFlag.Value.String(), "step flag not loaded from config")
										assert.Equal(t, "outfile.json", outfileFlag.Value.String(), "outfile flag not loaded from config")
									} else {
										assert.Equal(t, "", stepNameFlag.Value.String(), "step flag should remain empty")
									}
								}
							case "verify":
								keyFlag := cmd.Flags().Lookup("key")
								if tt.configYaml != "" && tt.configPath == "valid-slices.yaml" {
									assert.Equal(t, "[key1.pem,key2.pem]", keyFlag.Value.String(), "key slice flag not loaded correctly")
								} else {
									assert.Equal(t, "", keyFlag.Value.String(), "key flag should remain empty")
								}
							}
						}
					}
				}
			}
		})
	}
}
