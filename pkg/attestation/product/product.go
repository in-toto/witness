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
	"encoding/json"
	"net/http"
	"os"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/file"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "product"
	Type    = "https://witness.testifysec.com/attestations/product/v0.1"
	RunType = attestation.Internal
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	Products      map[string]attestation.Product `json:"products"`
	baseArtifacts map[string]cryptoutil.DigestSet
}

func fromDigestMap(digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
	products := make(map[string]attestation.Product)
	for fileName, digestSet := range digestMap {
		mimeType := "unknown"
		f, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
		if err == nil {
			mimeType, err = getFileContentType(f)
			if err != nil {
				mimeType = "unknown"
			}
			f.Close()
		}

		defer f.Close()
		products[fileName] = attestation.Product{
			MimeType: mimeType,
			Digest:   digestSet,
		}
	}

	return products
}

func (a Attestor) Name() string {
	return Name
}

func (a Attestor) Type() string {
	return Type
}

func (rc *Attestor) RunType() attestation.RunType {
	return RunType
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	baseArtifacts, err := ctx.GetMaterials()
	if err != nil {
		return err
	}

	a.baseArtifacts = baseArtifacts
	products, err := file.RecordArtifacts(ctx.WorkingDir(), a.baseArtifacts, ctx.Hashes(), map[string]struct{}{})
	if err != nil {
		return err
	}

	a.Products = fromDigestMap(products)
	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Products)
}

func (a *Attestor) GetProducts() map[string]attestation.Product {
	return a.Products
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range a.Products {
		subjects[productName] = product.Digest
	}

	return subjects
}

func getFileContentType(file *os.File) (string, error) {
	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	contentType := http.DetectContentType(buffer)
	return contentType, nil
}
