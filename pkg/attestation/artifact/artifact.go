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

package artifact

import (
	"crypto"
	"encoding/json"
	"io/fs"
	"path/filepath"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name = "Artifact"
	Type = "https://witness.testifysec.com/attestations/Artifact/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type Option func(*Attestor)

func WithBaseArtifacts(baseArtifacts map[string]cryptoutil.DigestSet) Option {
	return func(attestor *Attestor) {
		attestor.baseArtifacts = baseArtifacts
	}
}

type Attestor struct {
	Artifacts     map[string]cryptoutil.DigestSet `json:"artifacts"`
	baseArtifacts map[string]cryptoutil.DigestSet
}

func (a Attestor) Name() string {
	return Name
}

func (a Attestor) Type() string {
	return Type
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}
	for _, opt := range opts {
		opt(attestor)
	}

	return attestor
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	artifacts, err := recordArtifacts(ctx.WorkingDir(), a.baseArtifacts, ctx.Hashes(), map[string]struct{}{})
	if err != nil {
		return err
	}

	a.Artifacts = artifacts
	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Artifacts)
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	attestations := make(map[string]cryptoutil.DigestSet)
	return json.Unmarshal(data, &attestations)
}

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func recordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []crypto.Hash, visitedSymlinks map[string]struct{}) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)
	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(basePath, path)
		if err != nil {
			return err
		}

		if info.Mode()&fs.ModeSymlink != 0 {
			// if this is a symlink, eval the true path and eval any artifacts in the symlink. we record every symlink we've visited to prevent infinite loops
			linkedPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}

			if _, ok := visitedSymlinks[linkedPath]; ok {
				return nil
			}

			visitedSymlinks[linkedPath] = struct{}{}
			symlinkedArtifacts, err := recordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks)
			if err != nil {
				return err
			}

			for artifactPath, artifact := range symlinkedArtifacts {
				// all artifacts in the symlink should be recorded relative to our basepath
				joinedPath := filepath.Join(relPath, artifactPath)
				if shouldRecord(joinedPath, artifact, baseArtifacts) {
					artifacts[filepath.Join(relPath, artifactPath)] = artifact
				}
			}

			return nil
		}

		artifact, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			return err
		}

		if shouldRecord(relPath, artifact, baseArtifacts) {
			artifacts[relPath] = artifact
		}

		return nil
	})

	return artifacts, err
}

// shouldRecord determines whether artifact should be recorded.
// if the artifact is already in baseArtifacts, check if it's changed
// if it is not equal to the existing artifact, return true, otherwise return false
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet) bool {
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}

	return true
}
