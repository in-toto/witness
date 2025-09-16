package oci

import (
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ResolveDigest returns the digest of the image at the reference.
//
// If the reference is by digest already, it simply extracts the digest.
// Otherwise, it looks up the digest from the registry.

func ResolveDigest(ref name.Reference, opts ...Option) (name.Digest, error) {
	o := makeOptions(ref.Context(), opts...)
	if d, ok := ref.(name.Digest); ok {
		return d, nil
	}
	desc, err := remote.Get(ref, o.ROpt...)
	if err != nil {
		return name.Digest{}, err
	}
	return ref.Context().Digest(desc.Digest.String()), nil
}
