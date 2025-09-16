// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"fmt"
	"reflect"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/go-witness/log"
)

type SignOption func(*signOpts)

type signOpts struct {
	dd  DupeDetector
	ro  ReplaceOp
	rct bool
}
type DupeDetector interface {
	Find(Signatures, Signature) (Signature, error)
}

type ReplaceOp interface {
	Replace(Signatures, Signature) (Signatures, error)
}
type signedImage struct {
	SignedImage
	// sig         Signature
	att         Signature
	so          *signOpts
	attachments map[string]File
}

type signedUnknown struct {
	SignedEntityInterface
	// sig         Signature
	att         Signature
	so          *signOpts
	attachments map[string]File
}

type signedImageIndex struct {
	ociSignedImageIndex
	// sig         Signature
	att         Signature
	so          *signOpts
	attachments map[string]File
}
type ociSignedImageIndex SignedImageIndex

// normalize turns image digests into tags with optional prefix & suffix:
// sha256:d34db33f -> [prefix]sha256-d34db33f[.suffix]
func normalize(h v1.Hash, prefix string, suffix string) string {
	return normalizeWithSeparator(h, prefix, suffix, "-")
}

func makeSignOpts(opts ...SignOption) *signOpts {
	so := &signOpts{}
	for _, opt := range opts {
		opt(so)
	}
	return so
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

func AttachAttestationToEntity(se SignedEntityInterface, att Signature, opts ...SignOption) (SignedEntityInterface, error) {
	switch obj := se.(type) {
	case SignedImage:
		log.Info("oci.SignedImage:")
		return AttachAttestationToImage(obj, att, opts...)
	case SignedImageIndex:
		log.Info("oci.SignedImageIndex:")
		return AttachAttestationToImageIndex(obj, att, opts...)
	default:
		log.Info("AttachAttestationToUnknown:")
		return AttachAttestationToUnknown(obj, att, opts...)
	}
}

func AttachAttestationToImage(si SignedImage, att Signature, opts ...SignOption) (SignedImage, error) {
	return &signedImage{
		SignedImage: si,
		att:         att,
		attachments: make(map[string]File),
		so:          makeSignOpts(opts...),
	}, nil
}

func AttachAttestationToImageIndex(sii SignedImageIndex, att Signature, opts ...SignOption) (SignedImageIndex, error) {
	return &signedImageIndex{
		ociSignedImageIndex: sii,
		att:                 att,
		attachments:         make(map[string]File),
		so:                  makeSignOpts(opts...),
	}, nil
}

// AttachAttestationToUnknown attaches the provided attestation to the provided image.
func AttachAttestationToUnknown(se SignedEntityInterface, att Signature, opts ...SignOption) (SignedEntityInterface, error) {
	return &signedUnknown{
		SignedEntityInterface: se,
		att:                   att,
		attachments:           make(map[string]File),
		so:                    makeSignOpts(opts...),
	}, nil
}
