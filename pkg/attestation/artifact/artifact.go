package artifact

import (
	"crypto"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	witcrypt "gitlab.com/testifysec/witness-cli/pkg/crypto"
)

const (
	Name = "Artifact"
	URI  = "https://witness.testifysec.com/attestations/Artifact/v0.1"
)

func init() {
	attestation.RegisterAttestation(Name, URI, func() attestation.Attestor {
		return New()
	})
}

type Option func(*Attestor)

func WithBaseArtifacts(baseArtifacts map[string]map[crypto.Hash]string) Option {
	return func(attestor *Attestor) {
		attestor.baseArtifacts = baseArtifacts
	}
}

type Attestor struct {
	Artifacts     map[string]map[crypto.Hash]string
	baseArtifacts map[string]map[crypto.Hash]string
}

func (a Attestor) Name() string {
	return Name
}

func (a Attestor) URI() string {
	return URI
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
	attestations := make(map[string]map[crypto.Hash][]byte)
	return json.Unmarshal(data, &attestations)
}

// equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, equal will return false.
// If any digest from common hash functions differ between the two artifacts, equal will return false.
func equal(first, second map[crypto.Hash]string) bool {
	hasMatchingDigest := false
	for hash, digest := range first {
		otherDigest, ok := second[hash]
		if !ok {
			continue
		}

		if digest == otherDigest {
			hasMatchingDigest = true
		} else {
			return false
		}
	}

	return hasMatchingDigest
}

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func recordArtifacts(basePath string, baseArtifacts map[string]map[crypto.Hash]string, hashes []crypto.Hash) (map[string]map[crypto.Hash]string, error) {
	artifacts := make(map[string]map[crypto.Hash]string)
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

		artifact, err := recordArtifact(relPath, hashes)
		if err != nil {
			return err
		}

		// if the artifact is already in baseArtifacts, check if it's changed
		// if it is not equal to the existing artifact, record it, otherwise skip it
		previous, ok := baseArtifacts[relPath]
		if ok && equal(artifact, previous) {
			return nil
		}

		artifacts[relPath] = artifact
		return nil
	})

	return artifacts, err
}

func recordArtifact(path string, hashes []crypto.Hash) (map[crypto.Hash]string, error) {
	artifact := make(map[crypto.Hash]string)
	f, err := os.Open(path)
	if err != nil {
		return artifact, err
	}

	for _, h := range hashes {
		digest, err := witcrypt.Digest(f, h)
		if err != nil {
			return artifact, err
		}

		artifact[h] = string(witcrypt.HexEncode(digest))
	}

	return artifact, nil
}
