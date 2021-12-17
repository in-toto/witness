package main

import (
	"crypto"
	"fmt"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/attestation/artifact"
	"github.com/testifysec/witness/pkg/attestation/commandrun"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name = "oci"
	Type = "https://witness.testifysec.com/attestations/oci/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	ImageDigest string               `json:"image_digest"`
	TarDigest   cryptoutil.DigestSet `json:"tar_digest"`
	Manifest    string               `json:"manifest"`
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

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {

	var products *artifact.Attestor

	for _, attestor := range ctx.CompletedAttestors() {
		if cmdAttestor, ok := attestor.(*commandrun.CommandRun); ok {
			products = cmdAttestor.Products
		}
	}

	for key, hash := range products.Artifacts {
		path := filepath.Join(ctx.WorkingDir(), key)
		img, err := tarball.ImageFromPath(path, nil)
		if err == nil {

			digest, err := img.Digest()
			if err != nil {
				return err
			}

			a.ImageDigest = digest.String()
			a.TarDigest = hash
			m, err := img.RawManifest()
			if err != nil {
				return err
			}

			a.Manifest = string(m)

			//Only support one image per run for now
			return nil

		}
	}
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	tarSHA256 := a.TarDigest[crypto.SHA256]

	imageDigestName := fmt.Sprintf("img:mainifest:digest:%s", a.ImageDigest)
	tarDigestName := fmt.Sprintf("tar:digest:%s", tarSHA256)

	return map[string]cryptoutil.DigestSet{
		imageDigestName: {
			crypto.SHA256: a.ImageDigest,
		},
		tarDigestName: a.TarDigest,
	}
}
