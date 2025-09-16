package oci

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/go-witness/log"
	"github.com/sigstore/cosign/v2/pkg/cosign/env"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

type SignedEntityInterface interface {
	// Digest returns the sha256 of this image's manifest.
	Digest() (v1.Hash, error)

	// Signatures returns the set of signatures currently associated with this
	// entity, or the empty equivalent if none are found.
	Signatures() (Signatures, error)

	// Attestations returns the set of attestations currently associated with this
	// entity, or the empty equivalent if none are found.
	// Attestations are just like a Signature, but they do not contain
	// Base64Signature because it's baked into the payload.
	Attestations() (Signatures, error)

	// Attachment returns a named entity associated with this entity, or error if not found.
	Attachment(name string) (File, error)
}

// AttachAttestationOptions is the top level wrapper for the attach attestation command.
type AttachAttestationOptions struct {
	Attestations     []string
	SkipVerification bool // Add skip verification option
	Registry         RegistryOptions
}

type File interface {
	// FileMediaType retrieves the media type of the File
	FileMediaType() (types.MediaType, error)

	// Payload fetches the opaque data that is being signed.
	// This will always return data when there is no error.
	Payload() ([]byte, error)
}
type SignedImage interface {
	v1.Image
	SignedEntityInterface
}
type SignedImageIndex interface {
	v1.ImageIndex
	SignedEntityInterface

	// SignedImage is the same as Image, but provides accessors for the nested
	// image's signed metadata.
	SignedImage(v1.Hash) (SignedImage, error)

	// SignedImageIndex is the same as ImageIndex, but provides accessors for
	// the nested image index's signed metadata.
	SignedImageIndex(v1.Hash) (SignedImageIndex, error)
}

type image struct {
	v1.Image
	ref name.Reference
	opt *options
	// opt *RemoteOptions
}

type index struct {
	v1.ImageIndex
	ref name.Reference
	opt *options
	// opt *RemoteOptions
}

func (si *image) Signatures() (Signatures, error) {
	// Simplified signature retrieval logic
	log.Info("image Signatures")
	return signatures(si, si.opt)
}

func (si *image) Attestations() (Signatures, error) {
	// Simplified attestation retrieval logic
	log.Info("image Attestations")
	return attestations(si, si.opt)
}

// attestations is a shared implementation of the oci.Signed* Attestations method.
func attestations(digestable SignedEntityInterface, o *options) (Signatures, error) {
	log.Info("attestations")
	h, err := digestable.Digest()
	if err != nil {
		return nil, err
	}
	log.Info(h)
	return SignaturesIndexImage(o.TargetRepository.Tag(normalize(h, "", o.AttestationSuffix)), o.OriginalOptions...)
}
func signatures(digestable SignedEntityInterface, o *options) (Signatures, error) {
	h, err := digestable.Digest()
	if err != nil {
		return nil, err
	}
	return SignaturesIndexImage(o.TargetRepository.Tag(normalize(h, "", o.SignatureSuffix)), o.OriginalOptions...)
}

func (si *image) Attachment(name string) (File, error) {
	// Simplified attachment retrieval logic
	return nil, nil
}

// Implement SignedEntity for index
func (si *index) Signatures() (Signatures, error) {
	log.Info("index Signatures")
	return signatures(si, si.opt)
}

func (si *index) Attestations() (Signatures, error) {
	log.Info("index Attestations")
	return attestations(si, si.opt)
}

func (si *index) Attachment(name string) (File, error) {
	return nil, nil
}

type sigs struct {
	v1.Image
}

const maxLayers = 1000

func (s *sigs) Get() ([]Signature, error) {
	m, err := s.Manifest()
	if err != nil {
		return nil, err
	}
	numLayers := int64(len(m.Layers))
	if numLayers > maxLayers {
		// return nil, NewMaxLayersExceeded(numLayers, maxLayers)
		return nil, fmt.Errorf("number of layers (%d) exceeded the limit (%d)", numLayers, maxLayers)

	}
	signatures := make([]Signature, 0, len(m.Layers))
	for _, desc := range m.Layers {
		layer, err := s.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, New(layer, desc))
	}
	return signatures, nil
}

func New(l v1.Layer, desc v1.Descriptor) Signature {
	return &sigLayer{
		Layer: l,
		desc:  desc,
	}
}

type sigLayer struct {
	v1.Layer
	desc v1.Descriptor
}

func (s *sigLayer) Annotations() (map[string]string, error) {
	return s.desc.Annotations, nil
}
func (s *sigLayer) Payload() ([]byte, error) {
	size, err := s.Size()
	if err != nil {
		return nil, err
	}
	err = CheckSize(uint64(size))
	if err != nil {
		return nil, err
	}
	// Compressed is a misnomer here, we just want the raw bytes from the registry.
	r, err := s.Compressed()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

const defaultMaxSize = uint64(134217728) // 128MiB

func CheckSize(size uint64) error {
	maxSize := defaultMaxSize
	maxSizeOverride, exists := env.LookupEnv(env.VariableMaxAttachmentSize)
	if exists {
		var err error
		maxSize, err = humanize.ParseBytes(maxSizeOverride)
		if err != nil {
			maxSize = defaultMaxSize
		}
	}
	if size > maxSize {
		return fmt.Errorf("size of layer (%d) exceeded the limit (%d)", size, maxSize)
	}
	return nil
}

// Signature implements oci.Signature
func (s *sigLayer) Signature() ([]byte, error) {
	b64sig, err := s.Base64Signature()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(b64sig)
}

const sigkey = "org.in-toto.witness/attestations"

func (s *sigLayer) Base64Signature() (string, error) {
	b64sig, ok := s.desc.Annotations[sigkey]
	if !ok {
		return "", fmt.Errorf("signature layer %s is missing %q annotation", s.desc.Digest, sigkey)
	}
	return b64sig, nil
}
func SignaturesIndexImage(ref name.Reference, opts ...Option) (Signatures, error) {
	o := makeOptions(ref.Context(), opts...)
	img, err := remote.Image(ref, o.ROpt...)
	log.Info("img %s", img)
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			return nil, te
		}
		// return empty.Signatures(), nil
		return EmptySignatures(), nil
	} else if err != nil {
		return nil, err
	}
	return &sigs{
		Image: img,
	}, nil
}

// If signatures index doesn't exist, return an *empty* Signatures implementation
func EmptySignatures() Signatures {
	base := empty.Image
	if !oci.DockerMediaTypes() {
		base = mutate.MediaType(base, types.OCIManifestSchema1)
		base = mutate.ConfigMediaType(base, types.OCIConfigJSON)
	}
	return &emptyImage{
		Image: base,
	}
}

type emptyImage struct {
	v1.Image
}

// Get implements oci.Signatures
func (*emptyImage) Get() ([]Signature, error) {
	return nil, nil
}
