// Copyright 2022 The Witness Contributors
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
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/log"
	"github.com/spf13/cobra"
)

var DefaultAttestors = []string{"environment", "git"}

type RunOptions struct {
	SignerOptions            SignerOptions
	KMSSignerProviderOptions KMSSignerProviderOptions
	ArchivistaOptions        ArchivistaOptions
	WorkingDir               string
	Attestations             []string
	Hashes                   []string
	OutFilePath              string
	StepName                 string
	Tracing                  bool
	TimestampServers         []string
	AttestorOptSetters       map[string][]func(attestation.Attestor) (attestation.Attestor, error)
	EnvFilterSensitiveVars   bool
	EnvDisableSensitiveVars  bool
	EnvAddSensitiveKeys      []string
	EnvExcludeSensitiveKeys  []string
}

var RequiredRunFlags = []string{
	"step",
}

var OneRequiredPKSignFlags = []string{
	"signer-file-key-path",
	"policy-ca",
	"signer-kms-ref",
}

func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.SignerOptions.AddFlags(cmd)
	ro.ArchivistaOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory from which commands will run")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", DefaultAttestors, "Attestations to record ('product' and 'material' are always recorded)")
	cmd.Flags().StringSliceVar(&ro.Hashes, "hashes", []string{"sha256"}, "Hashes selected for digest calculation. Defaults to SHA256")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to write signed data to")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().BoolVarP(&ro.Tracing, "trace", "r", false, "Enable tracing for the command")
	cmd.Flags().StringSliceVarP(&ro.TimestampServers, "timestamp-servers", "t", []string{}, "Timestamp Authority Servers to use when signing envelope")

	// Environment variables flags
	cmd.Flags().BoolVarP(&ro.EnvFilterSensitiveVars, "env-filter-sensitive-vars", "", false, "Switch from obfuscate to filtering variables which removes them from the output completely.")
	cmd.Flags().BoolVarP(&ro.EnvDisableSensitiveVars, "env-disable-default-sensitive-vars", "", false, "Disable the default list of sensitive vars and only use the items mentioned by --add-sensitive-key.")
	cmd.Flags().StringSliceVar(&ro.EnvAddSensitiveKeys, "env-add-sensitive-key", []string{}, "Add keys or globs (e.g. '*TEXT') to the list of sensitive environment keys.")
	cmd.Flags().StringSliceVar(&ro.EnvExcludeSensitiveKeys, "env-exclude-sensitive-key", []string{}, "Exclude specific keys from the list of sensitive environment keys. Note: This does not support globs.")

	cmd.MarkFlagsRequiredTogether(RequiredRunFlags...)

	attestationRegistrations := attestation.RegistrationEntries()
	ro.AttestorOptSetters = addFlagsFromRegistry("attestor", attestationRegistrations, cmd)

	ro.KMSSignerProviderOptions.AddFlags(cmd)
}

type ArchivistaOptions struct {
	Enable bool
	Url    string
}

func (o *ArchivistaOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Enable, "enable-archivista", false, "Use Archivista to store or retrieve attestations")
	cmd.Flags().BoolVar(&o.Enable, "enable-archivist", false, "Use Archivista to store or retrieve attestations (deprecated)")
	if err := cmd.Flags().MarkHidden("enable-archivist"); err != nil {
		log.Errorf("failed to hide enable-archivist flag: %w", err)
	}

	cmd.Flags().StringVar(&o.Url, "archivista-server", "https://archivista.testifysec.io", "URL of the Archivista server to store or retrieve attestations")
	cmd.Flags().StringVar(&o.Url, "archivist-server", "https://archivista.testifysec.io", "URL of the Archivista server to store or retrieve attestations (deprecated)")
	if err := cmd.Flags().MarkHidden("archivist-server"); err != nil {
		log.Debugf("failed to hide archivist-server flag: %w", err)
	}
}
