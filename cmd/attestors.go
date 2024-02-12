// Copyright 2021 The Witness Contributors
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

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/witness/options"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func AttestorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attestors",
		Short:             "List all available attestors",
		Long:              "Lists all the available attestors in Witness with supporting information",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttestors(cmd.Context())
		},
	}

	return cmd
}

func runAttestors(ctx context.Context) error {
	items := [][]string{}
	entries := attestation.RegistrationEntries()
	for _, entry := range entries {
		name := entry.Factory().Name()
		// NOTE: This is a workaround to avoid printing the command-run attestor. We should mark it in the registry as such somehow.
		if name == "command-run" {
			continue
		}

		for _, a := range alwaysRunAttestors {
			if name == a.Name() {
				name = name + " (always run)"
			}
		}

		for _, a := range options.DefaultAttestors {
			if name == a {
				name = name + " (default)"
			}
		}

		runType := entry.Factory().RunType()
		item := []string{name, entry.Factory().Type(), fmt.Sprintf("%v", runType)}
		items = append(items, item)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "Type", "RunType"})
	table.SetAutoMergeCells(false)
	table.SetRowLine(false)
	table.AppendBulk(items)
	table.Render()

	return nil
}
