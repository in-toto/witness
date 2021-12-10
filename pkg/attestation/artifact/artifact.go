package artifact

import (
	"crypto"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/testifysec/witness/pkg/attestation"
	witcrypt "github.com/testifysec/witness/pkg/crypto"
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

func WithBaseArtifacts(baseArtifacts map[string]witcrypt.DigestSet) Option {
	return func(attestor *Attestor) {
		attestor.baseArtifacts = baseArtifacts
	}
}

type Attestor struct {
	Artifacts     map[string]witcrypt.DigestSet `json:"artifacts"`
	baseArtifacts map[string]witcrypt.DigestSet
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
	artifacts, err := recordArtifacts(ctx.WorkingDir(), a.baseArtifacts, ctx.Hashes())
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
	attestations := make(map[string]witcrypt.DigestSet)
	return json.Unmarshal(data, &attestations)
}

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func recordArtifacts(basePath string, baseArtifacts map[string]witcrypt.DigestSet, hashes []crypto.Hash) (map[string]witcrypt.DigestSet, error) {
	artifacts := make(map[string]witcrypt.DigestSet)
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

		artifact, err := recordArtifact(path, hashes)
		if err != nil {
			return err
		}

		// if the artifact is already in baseArtifacts, check if it's changed
		// if it is not equal to the existing artifact, record it, otherwise skip it
		previous, ok := baseArtifacts[relPath]
		if ok && artifact.Equal(previous) {
			return nil
		}

		artifacts[relPath] = artifact
		return nil
	})

	return artifacts, err
}

func recordArtifact(path string, hashes []crypto.Hash) (witcrypt.DigestSet, error) {
	artifact := make(witcrypt.DigestSet)
	f, err := os.Open(path)
	if err != nil {
		return artifact, err
	}

	defer f.Close()
	for _, h := range hashes {
		digest, err := witcrypt.Digest(f, h)
		if err != nil {
			return artifact, err
		}

		artifact[h] = string(witcrypt.HexEncode(digest))
	}

	return artifact, nil
}
