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
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func (so *signOpts) dedupeAndReplace(sig Signature, basefn func() (Signatures, error)) (Signatures, error) {
	base, err := basefn()
	if err != nil {
		return nil, err
	} else if sig == nil {
		return base, nil
	}
	if so.dd != nil {
		if existing, err := so.dd.Find(base, sig); err != nil {
			return nil, err
		} else if existing != nil {
			// Just return base if the signature is redundant
			return base, nil
		}
	}
	if so.ro != nil {
		replace, err := so.ro.Replace(base, sig)
		if err != nil {
			return nil, err
		}
		return ReplaceSignatures(replace)
	}
	return AppendSignatures(base, so.rct, sig)
}

// AppendSignatures produces a new Signatures with the provided signatures
// appended to the provided base signatures.
func AppendSignatures(base Signatures, recordCreationTimestamp bool, sigs ...Signature) (Signatures, error) {
	adds := make([]mutate.Addendum, 0, len(sigs))
	for _, sig := range sigs {
		// log.Info("sigs more Signature %s", sig)
		ann, err := sig.Annotations()
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{
			Layer:       sig,
			Annotations: ann,
		})
	}
	img, err := mutate.Append(base, adds...)
	if err != nil {
		return nil, err
	}

	if recordCreationTimestamp {
		t := time.Now()

		// Set the Created date to time of execution
		img, err = mutate.CreatedAt(img, v1.Time{Time: t})
		if err != nil {
			return nil, err
		}
	}

	return &sigAppender{
		Image: img,
		base:  base,
		sigs:  sigs,
	}, nil
}

// ReplaceSignatures produces a new Signatures provided by the base signatures
// replaced with the new Signatures.
func ReplaceSignatures(base Signatures) (Signatures, error) {
	sigs, err := base.Get()
	if err != nil {
		return nil, err
	}
	adds := make([]mutate.Addendum, 0, len(sigs))
	for _, sig := range sigs {
		ann, err := sig.Annotations()
		if err != nil {
			return nil, err
		}
		adds = append(adds, mutate.Addendum{
			Layer:       sig,
			Annotations: ann,
		})
	}
	img, err := mutate.Append(EmptySignatures(), adds...)
	if err != nil {
		return nil, err
	}
	return &sigAppender{
		Image: img,
		base:  base,
		sigs:  []Signature{},
	}, nil
}

type sigAppender struct {
	v1.Image
	base Signatures
	sigs []Signature
}

var _ Signatures = (*sigAppender)(nil)

// Get implements Signatures
func (sa *sigAppender) Get() ([]Signature, error) {
	sl, err := sa.base.Get()
	if err != nil {
		return nil, err
	}
	sumLayers := int64(len(sl) + len(sa.sigs))
	if sumLayers > maxLayers {
		return nil, fmt.Errorf("number of layers (%d) exceeded the limit (%d)", sumLayers, maxLayers)
	}
	return append(sl, sa.sigs...), nil
}
