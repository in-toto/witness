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
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const AttestationTagSuffix = "att"

// Option is a functional option for remote operations.
type Option func(*options)

type options struct {
	SignatureSuffix   string
	AttestationSuffix string
	TargetRepository  name.Repository
	ROpt              []remote.Option
	NameOpts          []name.Option
	OriginalOptions   []Option
}

var defaultOptions = []remote.Option{
	remote.WithAuthFromKeychain(authn.DefaultKeychain),
}

func makeOptions(target name.Repository, opts ...Option) *options {
	o := &options{
		AttestationSuffix: AttestationTagSuffix,
		TargetRepository:  target,
		ROpt:              defaultOptions,

		// Keep the original options around for things that want
		// to call something that takes options!
		OriginalOptions: opts,
	}

	for _, option := range opts {
		option(o)
	}

	return o
}
