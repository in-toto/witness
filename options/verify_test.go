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

// Test VerifyOptions.AddFlags method
func TestVerifyOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	vo := VerifyOptions{
		VerifierOptions:            make(VerifierOptions),
		KMSVerifierProviderOptions: make(KMSVerifierProviderOptions),
		ArchivistaOptions:          ArchivistaOptions{},
	}

	// Add flags
	vo.AddFlags(cmd)

	// Test presence of flags
	flags := []string{
		"policy",
		"attestations",
		"artifactfile",
		"directory-path",
		"subjects",
		"publickey",
		"policy-ca", // deprecated but should still be added
		"policy-ca-roots",
		"policy-ca-intermediates",
		"policy-commonname",
		"policy-dns-names",
		"policy-emails",
		"policy-organizations",
		"policy-uris",
		"policy-timestamp-servers",
		"policy-fulcio-oidc-issuer",
		"policy-fulcio-build-trigger",
		"policy-fulcio-source-repository-digest",
		"policy-fulcio-run-invocation-uri",
		"policy-fulcio-source-repository-identifier",
		"policy-fulcio-source-repository-ref",
	}

	for _, name := range flags {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "Flag '%s' should be added", name)
	}

	// Test some of the flag defaults
	assert.Equal(t, "[]", cmd.Flags().Lookup("policy-ca-roots").DefValue, "Default policy-ca-roots should be empty array")
	assert.Equal(t, "[]", cmd.Flags().Lookup("policy-ca-intermediates").DefValue, "Default policy-ca-intermediates should be empty array")

	// Test that required flags are set
	assert.Equal(t, []string{"policy"}, RequiredVerifyFlags, "Required flags should include policy")
	assert.Contains(t, OneRequiredPKVerifyFlags, "publickey", "One required flags should include publickey")
	assert.Contains(t, OneRequiredSubjectFlags, "artifactfile", "One required subject flags should include artifactfile")
}
