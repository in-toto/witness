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

package syft

import (
	"bytes"
	"errors"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	container "github.com/google/go-containerregistry/pkg/v1"
	"github.com/testifysec/witness/pkg/attestation"
)

const (
	Name    = "syft"
	Type    = "https://witness.dev/attestations/syft/v0.1"
	RunType = attestation.PostRunType
)

var candidateMimeTypes = map[string]struct{}{
	"application/octet-stream": {},
	"application/x-tar":        {},
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Option func(*Attestor)

func WithSource(source string) Option {
	return func(a *Attestor) {
		a.sourceStr = source
	}
}

func WithImageSource(img container.Image, cacheDir string, additionalTags ...string) Option {
	return func(a *Attestor) {
		a.sourceImg = img
		a.imgCache = cacheDir
		a.additionalTags = additionalTags
	}
}

type Attestor struct {
	SBOM sbom.SBOM `json:"-"`

	sourceStr      string
	sourceImg      container.Image
	imgCache       string
	additionalTags []string
}

func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (*Attestor) Name() string {
	return Name
}

func (*Attestor) Type() string {
	return Type
}

func (*Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) source(ctx *attestation.AttestationContext) (*source.Source, func(), error) {
	var err error
	if a.sourceImg == nil && a.sourceStr == "" {
		a.sourceStr, err = a.candidate(ctx.Products())
		if err != nil {
			return nil, nil, err
		}
	}

	if a.sourceImg != nil {
		i := image.NewImage(a.sourceImg, a.imgCache, image.WithTags(a.additionalTags...))
		if err := i.Read(); err != nil {
			return nil, nil, err
		}

		src, err := source.NewFromImage(i, "")
		return &src, nil, err
	}

	srcInput, err := source.ParseInput(a.sourceStr, "", true)
	if err != nil {
		return nil, nil, err
	}

	return source.New(*srcInput, nil, []string{})

}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	src, srcCleanup, err := a.source(ctx)
	if srcCleanup != nil {
		defer srcCleanup()
	}

	if err != nil {
		return err
	}

	catalog, relationships, distro, err := syft.CatalogPackages(src, cataloger.DefaultConfig())
	if err != nil {
		return err
	}

	a.SBOM = sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name: "witness",
		},
	}

	a.SBOM.Artifacts.PackageCatalog = catalog
	a.SBOM.Artifacts.LinuxDistribution = distro
	a.SBOM.Relationships = append(a.SBOM.Relationships, relationships...)

	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	return syft.Encode(a.SBOM, syft.FormatByID(syft.JSONFormatID))
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	sbom, _, err := syft.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}

	a.SBOM = *sbom
	return nil
}

func (a *Attestor) ToCycloneDX() ([]byte, error) {
	return syft.Encode(a.SBOM, syft.FormatByID(syft.CycloneDxJSONFormatID))
}

func (a *Attestor) ToSPDX() ([]byte, error) {
	return syft.Encode(a.SBOM, syft.FormatByID(syft.SPDXJSONFormatID))
}

func (a *Attestor) candidate(products map[string]attestation.Product) (string, error) {

	for path, product := range products {
		if _, ok := candidateMimeTypes[product.MimeType]; ok {
			return path, nil
		}
	}

	return "", errors.New("no candidates")
}
