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

// Mock interface option for testing
type mockOption struct {
}

func (m *mockOption) AddFlags(cmd *cobra.Command) {
	cmd.Flags().String("mock-flag", "default", "mock flag description")
}

// Test Interface and implementation
func TestOptionsInterface(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	// Test that mockOption implements Interface
	var opt Interface = &mockOption{}
	opt.AddFlags(cmd)

	// Verify that flag was added
	flag := cmd.Flags().Lookup("mock-flag")
	assert.NotNil(t, flag, "Flag should be added by the mock option")
	assert.Equal(t, "default", flag.DefValue, "Default value should be set")
	assert.Equal(t, "mock flag description", flag.Usage, "Description should be set")
}
