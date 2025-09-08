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
	"context"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/require"
)

func Test_AttestorsCmd(t *testing.T) {
	cmd := AttestorsCmd()
	require.NotNil(t, cmd)
	require.Equal(t, "attestors", cmd.Use)
	require.Equal(t, 2, len(cmd.Commands()))
}

func Test_ListCmd(t *testing.T) {
	cmd := ListCmd()
	require.NotNil(t, cmd)
	require.Equal(t, "list", cmd.Use)
}

func Test_SchemaCmd(t *testing.T) {
	cmd := SchemaCmd()
	require.NotNil(t, cmd)
	require.Equal(t, "schema", cmd.Use)
}

func Test_runList(t *testing.T) {
	err := runList(context.Background())
	require.NoError(t, err)
}

func Test_runSchema(t *testing.T) {
	t.Run("without arguments", func(t *testing.T) {
		err := runSchema(context.Background(), []string{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "you must specify an attestor")
	})

	t.Run("with too many arguments", func(t *testing.T) {
		err := runSchema(context.Background(), []string{"one", "two"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "you can only get one attestor")
	})

	t.Run("with invalid attestor", func(t *testing.T) {
		err := runSchema(context.Background(), []string{"invalid-attestor"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Error getting attestor")
	})

	t.Run("with valid attestor", func(t *testing.T) {
		// Get a valid attestor name
		entries := attestation.RegistrationEntries()
		if len(entries) == 0 {
			t.Skip("No attestors registered, skipping test")
			return
		}

		validAttestor := entries[0].Factory().Name()
		err := runSchema(context.Background(), []string{validAttestor})
		require.NoError(t, err)
	})
}
