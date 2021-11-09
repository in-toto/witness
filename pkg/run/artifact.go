package run

import (
	"bytes"
	"crypto"
	"io/fs"
	"os"
	"path/filepath"

	witcrypt "gitlab.com/testifysec/witness-cli/pkg/crypto"
)

type Artifact struct {
	Name    string
	Digests map[crypto.Hash][]byte
}

// Equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, Equal will return false.
// If any digest from common hash functions differ between the two artifacts, Equal will return false.
func (a Artifact) Equal(other Artifact) bool {
	hasMatchingDigest := false
	for hash, digest := range a.Digests {
		otherDigest, ok := other.Digests[hash]
		if !ok {
			continue
		}

		if bytes.Equal(digest, otherDigest) {
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
func recordArtifacts(basePath string, baseArtifacts map[string]Artifact, hashes []crypto.Hash) (map[string]Artifact, error) {
	artifacts := make(map[string]Artifact)
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
		if ok && artifact.Equal(previous) {
			return nil
		}

		artifacts[relPath] = artifact
		return nil
	})

	return artifacts, err
}

func recordArtifact(path string, hashes []crypto.Hash) (Artifact, error) {
	artifact := Artifact{Name: path, Digests: make(map[crypto.Hash][]byte)}
	f, err := os.Open(path)
	if err != nil {
		return artifact, err
	}

	for _, h := range hashes {
		digest, err := witcrypt.Digest(f, h)
		if err != nil {
			return artifact, err
		}

		artifact.Digests[h] = digest
	}

	return artifact, nil
}
