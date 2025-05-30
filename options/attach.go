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

package options

import (
	"github.com/spf13/cobra"
)

// ImageSource defines the source of the image to attach attestations to
type ImageSource string

const (
	// ImageSourceDocker loads the image from the local Docker daemon
	ImageSourceDocker ImageSource = "docker"
	// ImageSourceTarball loads the image from a local tarball file
	ImageSourceTarball ImageSource = "tarball"
)

// AttachOptions contains options for attaching attestations to OCI artifacts
type AttachOptions struct {
	AttestationFilePaths []string
	Source               ImageSource
	TarballPath          string // Path to the tarball file when Source is ImageSourceTarball
}

var RequiredAttachFlags = []string{
	"attestation",
}

// AddFlags adds command line flags for the AttachOptions
func (ao *AttachOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&ao.AttestationFilePaths, "attestation", "a", []string{}, "Attestation files to attach to the OCI artifact")
	cmd.Flags().StringVar(&ao.TarballPath, "tarball-path", "", "Path to image tarball when source is 'tarball'")
	cmd.MarkFlagsRequiredTogether(RequiredAttachFlags...)
}
