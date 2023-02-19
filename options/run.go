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
	"fmt"

	"github.com/spf13/cobra"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/log"
)

type RunOptions struct {
	KeyOptions         KeyOptions
	ArchivistaOptions  ArchivistaOptions
	WorkingDir         string
	Attestations       []string
	OutFilePath        string
	StepName           string
	Tracing            bool
	TimestampServers   []string
	AttestorOptSetters map[string][]func(attestation.Attestor) (attestation.Attestor, error)
}

func (ro *RunOptions) AddFlags(cmd *cobra.Command) {
	ro.KeyOptions.AddFlags(cmd)
	ro.ArchivistaOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&ro.WorkingDir, "workingdir", "d", "", "Directory from which commands will run")
	cmd.Flags().StringSliceVarP(&ro.Attestations, "attestations", "a", []string{"environment", "git"}, "Attestations to record")
	cmd.Flags().StringVarP(&ro.OutFilePath, "outfile", "o", "", "File to which to write signed data.  Defaults to stdout")
	cmd.Flags().StringVarP(&ro.StepName, "step", "s", "", "Name of the step being run")
	cmd.Flags().BoolVar(&ro.Tracing, "trace", false, "Enable tracing for the command")
	cmd.Flags().StringSliceVar(&ro.TimestampServers, "timestamp-servers", []string{}, "Timestamp Authority Servers to use when signing envelope")

	attestationRegistrations := attestation.RegistrationEntries()
	for _, registration := range attestationRegistrations {
		for _, opt := range registration.Options {
			name := fmt.Sprintf("%s-%s", registration.Name, opt.Name())
			switch optT := opt.(type) {
			case attestation.ConfigOption[int]:
				{
					val := cmd.Flags().Int(name, optT.DefaultVal(), opt.Description())
					ro.AttestorOptSetters[registration.Type] = append(ro.AttestorOptSetters[registration.Type], func(a attestation.Attestor) (attestation.Attestor, error) {
						return optT.Setter()(a, *val)
					})
				}

			case attestation.ConfigOption[string]:
				{
					val := cmd.Flags().String(name, optT.DefaultVal(), opt.Description())
					ro.AttestorOptSetters[registration.Type] = append(ro.AttestorOptSetters[registration.Type], func(a attestation.Attestor) (attestation.Attestor, error) {
						return optT.Setter()(a, *val)
					})
				}

			case attestation.ConfigOption[[]string]:
				{
					val := cmd.Flags().StringSlice(name, []string{}, opt.Description())
					cmd.Flags().StringSlice(name, optT.DefaultVal(), opt.Description())
					ro.AttestorOptSetters[registration.Type] = append(ro.AttestorOptSetters[registration.Type], func(a attestation.Attestor) (attestation.Attestor, error) {
						return optT.Setter()(a, *val)
					})
				}

			default:
				log.Debugf("unrecognized attestor option type: %T", optT)
			}
		}
	}
}

type ArchivistaOptions struct {
	Enable bool
	Url    string
}

func (o *ArchivistaOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.Enable, "enable-archivista", false, "Use Archivista to store or retrieve attestations")
	cmd.Flags().BoolVar(&o.Enable, "enable-archivist", false, "Use Archivist to store or retrieve attestations (deprecated)")
	if err := cmd.Flags().MarkHidden("enable-archivist"); err != nil {
		log.Debugf("failed to hide enable-archivist flag: %v", err)
	}

	cmd.Flags().StringVar(&o.Url, "archivista-server", "https://archivista.testifysec.io", "URL of the Archivista server to store or retrieve attestations")
	cmd.Flags().StringVar(&o.Url, "archivist-server", "https://archivista.testifysec.io", "URL of the Archivista server to store or retrieve attestations (deprecated)")
	if err := cmd.Flags().MarkHidden("archivist-server"); err != nil {
		log.Debugf("failed to hide archivist-server flag: %v", err)
	}
}
