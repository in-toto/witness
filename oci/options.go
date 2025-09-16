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
	// TODO(mattmoor): Incorporate user agent.
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
