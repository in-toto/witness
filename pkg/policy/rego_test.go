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
