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

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// Test RootOptions.AddFlags method
func TestRootOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	ro := &RootOptions{}
	ro.AddFlags(cmd)

	// Test presence of flags
	flags := []string{
		"config",
		"log-level",
		"debug-cpu-profile-file",
		"debug-mem-profile-file",
	}

	for _, name := range flags {
		flag := cmd.PersistentFlags().Lookup(name)
		assert.NotNil(t, flag, "Flag '%s' should be added", name)
	}

	// Test flag defaults
	assert.Equal(t, ".witness.yaml", cmd.PersistentFlags().Lookup("config").DefValue, "Default config path should be set correctly")
	assert.Equal(t, "info", cmd.PersistentFlags().Lookup("log-level").DefValue, "Default log-level should be 'info'")
	assert.Equal(t, "", cmd.PersistentFlags().Lookup("debug-cpu-profile-file").DefValue, "Default CPU profile file should be empty")
	assert.Equal(t, "", cmd.PersistentFlags().Lookup("debug-mem-profile-file").DefValue, "Default memory profile file should be empty")

	// Test flag shorthand
	assert.Equal(t, "c", cmd.PersistentFlags().Lookup("config").Shorthand, "Config flag should have shorthand 'c'")
	assert.Equal(t, "l", cmd.PersistentFlags().Lookup("log-level").Shorthand, "Log-level flag should have shorthand 'l'")
}
