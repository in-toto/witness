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

package git

import (
	"crypto"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name = "Git"
	Type = "https://witness.testifysec.com/attestations/Git/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type Status struct {
	Staging  string `json:"staging,omitempty"`
	Worktree string `json:"worktree,omitempty"`
}

type Attestor struct {
	CommitHash string            `json:"commithash"`
	Status     map[string]Status `json:"status,omitempty"`
}

func New() *Attestor {
	return &Attestor{
		Status: make(map[string]Status),
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	repo, err := git.PlainOpenWithOptions(ctx.WorkingDir(), &git.PlainOpenOptions{
		DetectDotGit: true,
	})

	if err != nil {
		return err
	}

	head, err := repo.Head()
	if err != nil {
		return err
	}

	a.CommitHash = head.Hash().String()
	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}

	status, err := worktree.Status()
	for file, status := range status {
		if status.Worktree == git.Unmodified && status.Staging == git.Unmodified {
			continue
		}

		attestStatus := Status{
			Worktree: statusCodeString(status.Worktree),
			Staging:  statusCodeString(status.Staging),
		}

		a.Status[file] = attestStatus
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjectName := fmt.Sprintf("git:%v", a.CommitHash)
	return map[string]cryptoutil.DigestSet{
		subjectName: {
			crypto.SHA1: a.CommitHash,
		},
	}
}

func statusCodeString(statusCode git.StatusCode) string {
	switch statusCode {
	case git.Unmodified:
		return "unmodified"
	case git.Untracked:
		return "untracked"
	case git.Modified:
		return "modified"
	case git.Added:
		return "added"
	case git.Deleted:
		return "deleted"
	case git.Renamed:
		return "renamed"
	case git.Copied:
		return "copied"
	case git.UpdatedButUnmerged:
		return "updated"
	default:
		return string(statusCode)
	}
}
