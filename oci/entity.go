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

import "github.com/in-toto/go-witness/log"

func makeSignOpts(opts ...SignOption) *signOpts {
	so := &signOpts{}
	for _, opt := range opts {
		opt(so)
	}
	return so
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
