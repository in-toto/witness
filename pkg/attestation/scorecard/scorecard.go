// Copyright 2022 The Witness Contributors
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

package scorecard

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "scorecard"
	Type    = "https://witness.testifysec.com/attestations/scorecard/v0.1"
	RunType = attestation.PostRunType
)

var mimeTypes = []string{"text/plain", "application/json"}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	Scorecard       jsonScorecardResultV2 `json:"scorecard"`
	ReportFile      string                `json:"reportFileName"`
	ReportDigestSet cryptoutil.DigestSet  `json:"reportDigestSet"`
	hashes          []crypto.Hash
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {

	a.hashes = ctx.Hashes()

	if err := a.getCanidate(ctx); err != nil {
		fmt.Printf("error getting canidate: %s\n", err)
		return err
	}

	return nil
}

func (a *Attestor) getCanidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		for _, mimeType := range mimeTypes {
			if !strings.Contains(mimeType, product.MimeType) {
				continue
			}
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			return fmt.Errorf("error calculating digest set from file: %s", path)
		}

		if !newDigestSet.Equal(product.Digest) {
			return fmt.Errorf("integrity error: product digest set does not match canidate digest set")
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file: %s", path)
		}

		reportBytes, err := ioutil.ReadAll(f)
		if err != nil {
			return fmt.Errorf("error reading file: %s", path)
		}

		//check to see if we can unmarshal into scorecard type
		if err := json.Unmarshal(reportBytes, &a.Scorecard); err != nil {
			fmt.Printf("error unmarshaling report: %s\n", err)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest

		return nil
	}
	return fmt.Errorf("no scorecard file found")
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	commitSubj := fmt.Sprintf("commithash:%s", a.Scorecard.Repo.Commit)
	nameSubj := fmt.Sprintf("reponame:%s", a.Scorecard.Repo.Name)

	subj := make(map[string]cryptoutil.DigestSet)

	subj[commitSubj] = cryptoutil.DigestSet{
		crypto.SHA1: a.Scorecard.Repo.Commit,
	}

	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(nameSubj), a.hashes)
	if err != nil {
		return nil
	}

	subj[nameSubj] = ds

	return subj
}

//Copy Pasted from https://github.com/ossf/scorecard/blob/main/pkg/json.go
type jsonScorecardResultV2 struct {
	Date           string              `json:"date"`
	Repo           jsonRepoV2          `json:"repo"`
	Scorecard      jsonScorecardV2     `json:"scorecard"`
	AggregateScore jsonFloatScore      `json:"score"`
	Checks         []jsonCheckResultV2 `json:"checks"`
	Metadata       []string            `json:"metadata"`
}

type jsonRepoV2 struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

type jsonScorecardV2 struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type jsonFloatScore float64

type jsonCheckResultV2 struct {
	Details []string                 `json:"details"`
	Score   int                      `json:"score"`
	Reason  string                   `json:"reason"`
	Name    string                   `json:"name"`
	Doc     jsonCheckDocumentationV2 `json:"documentation"`
}

type jsonCheckDocumentationV2 struct {
	URL   string `json:"url"`
	Short string `json:"short"`
	// Can be extended if needed.
}
