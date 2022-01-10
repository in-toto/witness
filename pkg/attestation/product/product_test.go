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

package product

import (
	"crypto"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

func Test_fromDigestMap(t *testing.T) {

	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []crypto.Hash{crypto.SHA256})
	if err != nil {
		t.Errorf("Failed to calculate digest set from bytes: %v", err)
	}

	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest

	result := fromDigestMap(testDigestSet)

	if len(result) != 1 {
		t.Errorf("Expected 1 product, got %d", len(result))
	}

	if result["test"].Digest.Equal(testDigest) == false {
		t.Errorf("Expected digest set to be %v, got %v", testDigest, result["test"])
	}

	t.Logf("Result: %v", spew.Sdump(result["test"]))
	t.Logf("Expected: %v", spew.Sdump(testDigest))
}

func TestAttestor_Name(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Expected Name to be %s, got %s", Name, a.Name())
	}
}

func TestAttestor_Type(t *testing.T) {
	a := New()
	if a.Type() != Type {
		t.Errorf("Expected Type to be %s, got %s", Type, a.Type())
	}
}

func TestAttestor_RunType(t *testing.T) {
	a := New()
	if a.RunType() != RunType {
		t.Errorf("Expected RunType to be %s, got %s", RunType, a.RunType())
	}
}

func TestAttestor_Attest(t *testing.T) {
	a := New()

	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []crypto.Hash{crypto.SHA256})
	if err != nil {
		t.Errorf("Failed to calculate digest set from bytes: %v", err)
	}

	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest

	a.baseArtifacts = testDigestSet

	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)
}
