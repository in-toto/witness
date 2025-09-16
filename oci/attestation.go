package oci

import (
	"fmt"
	"reflect"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/go-witness/log"
)

// normalize turns image digests into tags with optional prefix & suffix:
// sha256:d34db33f -> [prefix]sha256-d34db33f[.suffix]
func normalize(h v1.Hash, prefix string, suffix string) string {
	return normalizeWithSeparator(h, prefix, suffix, "-")
}

// normalizeWithSeparator turns image digests into tags with optional prefix & suffix:
// sha256:d34db33f -> [prefix]sha256[algorithmSeparator]d34db33f[.suffix]
func normalizeWithSeparator(h v1.Hash, prefix string, suffix string, algorithmSeparator string) string {
	if suffix == "" {
		return fmt.Sprint(prefix, h.Algorithm, algorithmSeparator, h.Hex)
	}
	return fmt.Sprint(prefix, h.Algorithm, algorithmSeparator, h.Hex, ".", suffix)
}

func WriteAttestations(repo name.Repository, se SignedEntityInterface, opts ...Option) error {
	if se == nil || (reflect.ValueOf(se).Kind() == reflect.Ptr && reflect.ValueOf(se).IsNil()) {
		return fmt.Errorf("WriteAttestations: signed entity is nil for repo %s", repo.String())
	}
	o := makeOptions(repo, opts...)

	// Access the signature list to publish
	atts, err := se.Attestations()
	if err != nil {
		return err
	}
	log.Info(atts)
	// Determine the tag to which these signatures should be published.
	h, err := se.Digest()
	if err != nil {
		return err
	}
	tag := o.TargetRepository.Tag(normalize(h, "", o.AttestationSuffix))

	// Write the Signatures image to the tag, with the provided remote.Options
	log.Info("remote.write")
	log.Info(tag)
	return remote.Write(tag, atts, o.ROpt...)
}
