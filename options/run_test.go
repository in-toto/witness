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

// Test RunOptions.AddFlags method
func TestRunOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	ro := RunOptions{
		SignerOptions:            make(SignerOptions),
		KMSSignerProviderOptions: make(KMSSignerProviderOptions),
		ArchivistaOptions:        ArchivistaOptions{},
	}

	// Add flags
	ro.AddFlags(cmd)

	// Test presence of flags
	flags := []string{
		"workingdir",
		"attestations",
		"dirhash-glob",
		"hashes",
		"outfile",
		"step",
		"trace",
		"timestamp-servers",
		"env-filter-sensitive-vars",
		"env-disable-default-sensitive-vars",
		"env-add-sensitive-key",
		"env-exclude-sensitive-key",
	}

	for _, name := range flags {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "Flag '%s' should be added", name)
	}

	// Test flag defaults
	assert.Equal(t, "[environment,git]", cmd.Flags().Lookup("attestations").DefValue, "Default attestations should be set correctly")
	assert.Equal(t, "[sha256]", cmd.Flags().Lookup("hashes").DefValue, "Default hash should be sha256")

	// Test AttestorOptSetters initialization
	assert.NotNil(t, ro.AttestorOptSetters, "Should initialize AttestorOptSetters map")
}

// Test ArchivistaOptions.AddFlags method
func TestArchivistaOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	ao := ArchivistaOptions{}
	ao.AddFlags(cmd)

	// Test presence of flags
	archivistaFlags := []string{
		"enable-archivista",
		"enable-archivist",
		"archivista-server",
		"archivist-server",
	}

	for _, name := range archivistaFlags {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "Flag '%s' should be added", name)
	}

	// Test defaults
	assert.Equal(t, "false", cmd.Flags().Lookup("enable-archivista").DefValue, "enable-archivista default should be false")
	assert.Equal(t, "https://archivista.testifysec.io", cmd.Flags().Lookup("archivista-server").DefValue, "Default server URL should be set correctly")
}
