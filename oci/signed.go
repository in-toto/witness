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
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/in-toto/go-witness/log"
)

// Your simplified SignedEntity function
func SignedEntity(ref name.Reference, options ...Option) (SignedEntityInterface, error) {
	// Get the remote descriptor
	o := makeOptions(ref.Context(), options...)
	desc, err := remote.Get(ref, o.ROpt...)
	if err != nil {
		var te *transport.Error
		if errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s", err)
		}
		return nil, err
	}

	// opt := &RemoteOptions{} // simplified options
	log.Infof("desc mediaType: %s", desc.MediaType)
	// Switch based on media type
	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		// Handle image index
		ii, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}
		log.Info("index")
		return &index{
			ImageIndex: ii,
			ref:        ref,
			opt:        o,
		}, nil

	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		// Handle single image
		img, err := desc.Image()
		if err != nil {
			return nil, err
		}
		log.Info("image")
		log.Info(img)
		return &image{
			Image: img,
			ref:   ref,
			opt:   o,
		}, nil

	default:
		return nil, fmt.Errorf("unknown media type: %v", desc.MediaType)
	}
}
