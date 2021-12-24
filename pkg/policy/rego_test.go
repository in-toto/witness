// Copyright 2021 The TestifySec Authors
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

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/attestation/git"
)

func TestRegoPolicy(t *testing.T) {
	attestor := git.Attestor{
		CommitHash: "123abc",
		Status:     map[string]git.Status{},
	}

	expectedReason := "unexpected changes to git repository"
	passPolicy := []RegoPolicy{
		{
			Name: "test",
			Module: []byte(`package witness.test
deny[msg]{
	count(input.status) > 0
	msg := "` + expectedReason + `"
}`),
		},
	}

	assert.NoError(t, EvaluateRegoPolicy(&attestor, passPolicy))
	attestor.Status["test"] = git.Status{Staging: "Modified"}
	err := EvaluateRegoPolicy(&attestor, passPolicy)
	assert.Error(t, err)
	require.IsType(t, ErrPolicyDenied{}, err)
	assert.ElementsMatch(t, []string{expectedReason}, err.(ErrPolicyDenied).Reasons)
}

func TestInvalidDeny(t *testing.T) {
	policies := []RegoPolicy{
		{
			Name: "invalid deny",
			Module: []byte(`package witness.test
deny[msg] {
	input.commithash != "123abc"
	msg := 0
}`),
		},
	}

	attestor := git.Attestor{
		CommitHash: "123",
	}

	err := EvaluateRegoPolicy(&attestor, policies)
	assert.IsType(t, ErrRegoInvalidData{}, err)
}
