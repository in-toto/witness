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

package oci

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "oci"
	Type    = "https://witness.testifysec.com/attestations/oci/v0.1"
	RunType = attestation.PostRunType
)

const mimeTypes = "application/octet-stream application/x-tar"

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	TarDigest    cryptoutil.DigestSet   `json:"tar_digest"`
	Manifest     []Manifest             `json:"manifest"`
	ImageTags    []string               `json:"image_tags"`
	LayerDiffIDs []cryptoutil.DigestSet `json:"diff_ids"`
	ImageID      cryptoutil.DigestSet   `json:"image_id"`
	ManifestRaw  []byte                 `json:"manifest_raw"`
	tarFilePath  string                 `json:"-"`
}

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func (m *Manifest) getLayerDIFFIDs(ctx *attestation.AttestationContext, tarFilePath string) ([]cryptoutil.DigestSet, error) {
	var layerDiffIDs []cryptoutil.DigestSet

	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}
		for _, layerFile := range m.Layers {
			if h.Name == layerFile {
				b := make([]byte, h.Size)

				_, err := tarReader.Read(b)
				if err != nil && err != io.EOF {
					return nil, err
				}

				layerDiffID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
				if err != nil {
					return nil, err
				}
				layerDiffIDs = append(layerDiffIDs, layerDiffID)
			}
		}
	}
	return layerDiffIDs, nil
}

func (m *Manifest) getImageID(ctx *attestation.AttestationContext, tarFilePath string) (cryptoutil.DigestSet, error) {
	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}

		if h.Name == m.Config {

			b := make([]byte, h.Size)
			_, err := tarReader.Read(b)
			if err != nil && err != io.EOF {
				return nil, err
			}

			imageID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
			if err != nil {
				fmt.Printf("error calculating image id: %s\n", err)
				return nil, err
			}

			return imageID, nil
		}
	}
	return nil, fmt.Errorf("could not find config in tar file")
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
	if err := a.getCanidate(ctx); err != nil {
		fmt.Printf("error getting canidate: %s\n", err)
		return err
	}

	if err := a.parseMaifest(ctx); err != nil {
		fmt.Printf("error parsing manifest: %s\n", err)
		return err
	}

	imageID, err := a.Manifest[0].getImageID(ctx, a.tarFilePath)
	if err != nil {
		fmt.Printf("error getting image id: %s\n", err)
		return err
	}

	layerDiffIDs, err := a.Manifest[0].getLayerDIFFIDs(ctx, a.tarFilePath)
	if err != nil {
		return err
	}

	a.ImageID = imageID
	a.LayerDiffIDs = layerDiffIDs
	a.ImageTags = a.Manifest[0].RepoTags

	return nil
}

func (a *Attestor) getCanidate(ctx *attestation.AttestationContext) error {
	products := ctx.GetProducts()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if !strings.Contains(mimeTypes, product.MimeType) {
			continue
		}

		if err := product.Digest.CheckIntegrity(path); err != nil {
			return fmt.Errorf("error checking integrity of product: %s", err)
		}

		a.TarDigest = product.Digest

		a.tarFilePath = path
		return nil
	}
	return fmt.Errorf("no tar file found")
}

func (a *Attestor) parseMaifest(ctx *attestation.AttestationContext) error {

	f, err := os.Open(a.tarFilePath)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(f)
	for {
		h, err := tarReader.Next()
		if err != nil {
			return err
		}
		if h.FileInfo().IsDir() {
			continue
		}
		if h.Name == "manifest.json" {
			a.ManifestRaw = make([]byte, h.Size)
			_, err = tarReader.Read(a.ManifestRaw)
			if err != nil || err == io.EOF {
				break
			}
			break
		}
	}

	err = json.Unmarshal(a.ManifestRaw, &a.Manifest)
	if err != nil {
		return err
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subj := make(map[string]cryptoutil.DigestSet)

	subj["tar_digest"] = a.TarDigest
	subj["image_id"] = a.ImageID
	for layer := range a.LayerDiffIDs {
		subj[fmt.Sprintf("layer_diff_id_%d", layer)] = a.LayerDiffIDs[layer]
	}
	return subj
}
