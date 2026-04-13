// Copyright 2024 The Witness Contributors
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

import "github.com/spf13/cobra"

type AttachOptions struct {
	ImageURI         string
	SkipVerification bool
}

func (ao *AttachOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&ao.ImageURI, "image-uri", "i", "", "Container image URI to attach attestations to (required)")
	_ = cmd.MarkFlagRequired("image-uri")
	cmd.Flags().BoolVar(&ao.SkipVerification, "skip-verification", false, "Skip checking if the attestation subject matches the image digest")
}
