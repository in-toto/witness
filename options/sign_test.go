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

// Test SignOptions.AddFlags method
func TestSignOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	so := SignOptions{
		SignerOptions:            make(SignerOptions),
		KMSSignerProviderOptions: make(KMSSignerProviderOptions),
	}

	// Add flags
	so.AddFlags(cmd)

	// Test presence of flags
	flags := []string{
		"datatype",
		"outfile",
		"infile",
		"timestamp-servers",
	}

	for _, name := range flags {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "Flag '%s' should be added", name)
	}

	// Test flag defaults
	assert.Equal(t, "https://witness.testifysec.com/policy/v0.1", cmd.Flags().Lookup("datatype").DefValue, "Default datatype should be set correctly")
	
	// Test required flags
	requiredFlags := RequiredSignFlags
	assert.Equal(t, []string{"infile", "outfile"}, requiredFlags, "Required flags should be set correctly")
}