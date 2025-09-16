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
	"context"
	"fmt"
	"runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

// Keychain is an alias of authn.Keychain to expose this configuration option to consumers of this lib
type Keychain = authn.Keychain

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = fmt.Sprintf("witness/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
)

// UserAgent returns the User-Agent string which `cosign` should send with HTTP requests.ß
func UserAgent() string {
	return uaString
}

// RegistryOptions is the wrapper for the registry options.
type RegistryOptions struct {
	AllowInsecure     bool
	AllowHTTPRegistry bool
	Keychain          Keychain
	AuthConfig        authn.AuthConfig
	// RegistryClientOpts allows overriding the result of GetRegistryClientOpts.
	RegistryClientOpts []remote.Option
}

func (o *RegistryOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.AllowInsecure, "allow-insecure-registry", false,
		"whether to allow insecure connections to registries (e.g., with expired or self-signed TLS certificates). Don't use this for anything but testing")

	cmd.Flags().BoolVar(&o.AllowHTTPRegistry, "allow-http-registry", false,
		"whether to allow using HTTP protocol while connecting to registries. Don't use this for anything but testing")

	cmd.Flags().StringVar(&o.AuthConfig.Username, "registry-username", "",
		"registry basic auth username")

	cmd.Flags().StringVar(&o.AuthConfig.Password, "registry-password", "",
		"registry basic auth password")

	cmd.Flags().StringVar(&o.AuthConfig.RegistryToken, "registry-token", "",
		"registry bearer auth token")
}
func (o *RegistryOptions) NameOptions() []name.Option {
	var nameOpts []name.Option
	if o.AllowHTTPRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	return nameOpts
}

// WithRemoteOptions is a functional option for overriding the default
// remote options passed to GGCR.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(o *options) {
		o.ROpt = opts
	}
}

func (o *RegistryOptions) ClientOpts(ctx context.Context) ([]Option, error) {
	opts := []Option{WithRemoteOptions(o.GetRegistryClientOpts(ctx)...)}
	// if o.RefOpts.TagPrefix != "" {
	// 	opts = append(opts, ociremote.WithPrefix(o.RefOpts.TagPrefix))
	// }
	// targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	// if err != nil {
	// 	return nil, err
	// }
	// if (targetRepoOverride != name.Repository{}) {
	// 	opts = append(opts, ociremote.WithTargetRepository(targetRepoOverride))
	// }
	return opts, nil
}

func (o *RegistryOptions) GetRegistryClientOpts(ctx context.Context) []remote.Option {
	if o.RegistryClientOpts != nil {
		ropts := o.RegistryClientOpts
		ropts = append(ropts, remote.WithContext(ctx))
		return ropts
	}
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(UserAgent()),
	}
	switch {
	case o.Keychain != nil:
		opts = append(opts, remote.WithAuthFromKeychain(o.Keychain))
	case o.AuthConfig.Username != "" && o.AuthConfig.Password != "":
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: o.AuthConfig.Username, Password: o.AuthConfig.Password}))
	case o.AuthConfig.RegistryToken != "":
		opts = append(opts, remote.WithAuth(&authn.Bearer{Token: o.AuthConfig.RegistryToken}))
	default:
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	// Reuse a remote.Pusher and a remote.Puller for all operations that use these opts.
	// This allows us to avoid re-authenticating for everying remote.Function we call,
	// which speeds things up a whole lot.
	pusher, err := remote.NewPusher(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}
	puller, err := remote.NewPuller(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(puller))
	}
	return opts
}
