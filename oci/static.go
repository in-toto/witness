// Copyright 2025 The Witness Contributors
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
	"crypto/x509"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type StaticOption func(*staticoptions)

const (
	SimpleSigningMediaType = "application/vnd.in-toto.witness.attestation.v1+json"
)

type Signatures interface {
	v1.Image // The low-level representation of the signatures

	// Get retrieves the list of signatures stored.
	Get() ([]Signature, error)
}

type Signature interface {
	v1.Layer

	// Annotations returns the annotations associated with this layer.
	Annotations() (map[string]string, error)

	// Payload fetches the opaque data that is being signed.
	// This will always return data when there is no error.
	Payload() ([]byte, error)

	// Signature fetches the raw signature
	// of the payload.  This will always return data when
	// there is no error.
	Signature() ([]byte, error)
}

type staticoptions struct {
	LayerMediaType  types.MediaType
	ConfigMediaType types.MediaType
	Annotations     map[string]string
}
type staticLayer struct {
	b      []byte
	b64sig string
	opts   *staticoptions
}

// Annotations implements Signature.
func (s *staticLayer) Annotations() (map[string]string, error) {
	panic("unimplemented")
}

// Cert implements Signature.
func (s *staticLayer) Cert() (*x509.Certificate, error) {
	panic("unimplemented")
}

// Compressed implements Signature.
func (s *staticLayer) Compressed() (io.ReadCloser, error) {
	panic("unimplemented")
}

// DiffID implements Signature.
func (s *staticLayer) DiffID() (v1.Hash, error) {
	panic("unimplemented")
}

// Digest implements Signature.
func (s *staticLayer) Digest() (v1.Hash, error) {
	panic("unimplemented")
}

// MediaType implements Signature.
func (s *staticLayer) MediaType() (types.MediaType, error) {
	panic("unimplemented")
}

// Payload implements Signature.
func (s *staticLayer) Payload() ([]byte, error) {
	panic("unimplemented")
}

// Signature implements Signature.
func (s *staticLayer) Signature() ([]byte, error) {
	panic("unimplemented")
}

// Size implements Signature.
func (s *staticLayer) Size() (int64, error) {
	panic("unimplemented")
}

// Uncompressed implements Signature.
func (s *staticLayer) Uncompressed() (io.ReadCloser, error) {
	panic("unimplemented")
}

// Verify that staticLayer implements both v1.Layer and Signature interfaces
var _ v1.Layer = (*staticLayer)(nil)
var _ Signature = (*staticLayer)(nil)

func makeStaticOptions(opts ...StaticOption) (*staticoptions, error) {
	o := &staticoptions{
		LayerMediaType:  SimpleSigningMediaType,
		ConfigMediaType: types.OCIConfigJSON,
		Annotations:     make(map[string]string),
	}

	for _, opt := range opts {
		opt(o)
	}
	return o, nil
}

// WithLayerMediaType sets the media type of the signature.
func WithLayerMediaType(mt types.MediaType) StaticOption {
	return func(o *staticoptions) {
		o.LayerMediaType = mt
	}
}

// WithConfigMediaType sets the media type of the signature.
func WithConfigMediaType(mt types.MediaType) StaticOption {
	return func(o *staticoptions) {
		o.ConfigMediaType = mt
	}
}

// WithAnnotations sets the annotations that will be associated.
func WithAnnotations(ann map[string]string) StaticOption {
	return func(o *staticoptions) {
		o.Annotations = ann
	}
}

// NewAttestation constructs a new oci.Signature from the provided options.
// Since Attestation is treated just like a Signature but the actual signature
// is baked into the payload, the Signature does not actually have
// the Base64Signature.
func NewAttestation(payload []byte, opts ...StaticOption) (Signature, error) {
	return NewSignature(payload, "", opts...)
}

// NewSignature constructs a new oci.Signature from the provided options.
func NewSignature(payload []byte, b64sig string, opts ...StaticOption) (Signature, error) {
	o, err := makeStaticOptions(opts...)
	if err != nil {
		return nil, err
	}
	return &staticLayer{
		b:      payload,
		b64sig: b64sig,
		opts:   o,
	}, nil
}
