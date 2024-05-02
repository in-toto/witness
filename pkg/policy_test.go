// Copyright 2024 The Witness Contributors
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

package pkg

import (
	"context"
	"errors"
	"testing"

	"github.com/in-toto/go-witness/dsse"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// Mock archivista client
type ArchivistaClienterMock struct {
	mock.Mock
	ArchivistaClienter
}

func (m *ArchivistaClienterMock) Download(ctx context.Context, path string) (dsse.Envelope, error) {
	args := m.Called()
	return dsse.Envelope{}, args.Error(1)
}

// Define test suite
type UTPolicySuite struct {
	suite.Suite
	mockedAC *ArchivistaClienterMock
}

func TestUTPolicySuite(t *testing.T) {
	suite.Run(t, new(UTPolicySuite))
}

// Setup test suite
func (ut *UTPolicySuite) SetupTest() {
	ut.mockedAC = &ArchivistaClienterMock{}

}

// Test LoadPolicy with file
func (ut *UTPolicySuite) TestLoadPolicyFile() {
	ctx := context.Background()
	policy := "../test/policy-hello-signed.json"

	// Load policy from file
	policyEnvelope, err := LoadPolicy(ctx, policy, nil)
	ut.NoError(err)
	ut.NotNil(policyEnvelope)
}

// Test LoadPolicy with file not found
func (ut *UTPolicySuite) TestLoadPolicyFileNotFound() {
	ctx := context.Background()
	policy := "notfound"

	// Load policy from file
	_, err := LoadPolicy(ctx, policy, nil)
	ut.Error(err)
	ut.Contains(err.Error(), "no such file or directory")
}

// Test LoadPolicy with archivista
func (ut *UTPolicySuite) TestLoadPolicyArchivista() {
	ctx := context.Background()
	policy := "testgitoid"

	// Mock archivista client
	ut.mockedAC.On("Download").Return(dsse.Envelope{}, nil)

	// Load policy from archivista
	policyEnvelope, err := LoadPolicy(ctx, policy, ut.mockedAC)
	ut.NoError(err)
	ut.NotNil(policyEnvelope)
}

// Test LoadPolicy with archivista not found
func (ut *UTPolicySuite) TestLoadPolicyArchivistaNotFound() {
	ctx := context.Background()
	policy := "testgitoid"

	// Mock archivista client
	ut.mockedAC.On("Download").Return(dsse.Envelope{}, errors.New("not found"))

	// Load policy from archivista
	_, err := LoadPolicy(ctx, policy, ut.mockedAC)
	ut.Error(err)
	ut.Contains(err.Error(), "failed to fetch policy from archivista")
}
