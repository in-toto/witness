// Copyright 2021 The Witness Contributors
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

package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/attestation"
)

func TestEnvironment(t *testing.T) {
	attestor := New()
	ctx, err := attestation.NewContext([]attestation.Attestor{attestor})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", "super secret")
	origVars := os.Environ()
	require.NoError(t, attestor.Attest(ctx))
	for _, env := range origVars {
		origKey, _ := splitVariable(env)
		if _, inBlockList := attestor.blockList[origKey]; inBlockList {
			require.NotContains(t, attestor.Variables, origKey)
		} else {
			require.Contains(t, attestor.Variables, origKey)
		}
	}
}
