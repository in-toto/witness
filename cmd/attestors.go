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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/witness/options"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

func AttestorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestors",
		Short: "Get information about available attestors",
		Long:  "Get information about all the available attestors in Witness",
	}

	cmd.AddCommand(SchemaCmd())
	cmd.AddCommand(ListCmd())

	return cmd
}

func ListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "list",
		Short:             "List all available attestors",
		Long:              "Lists all the available attestors in Witness with supporting information",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cmd.Context())
		},
	}
	return cmd
}

func SchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "schema",
		Short:             "Show the JSON schema of a specific attestor",
		Long:              "Print the JSON schema of the predicate that the specified attestor generates",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSchema(cmd.Context(), args)
		},
	}
	return cmd
}

func runList(ctx context.Context) error {
	items := [][]string{}
	entries := attestation.RegistrationEntries()
	for _, entry := range entries {
		name := entry.Factory().Name()

		for _, a := range alwaysRunAttestors {
			if name == a.Name() || name == "command-run" {
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
	table.Header([]string{"Name", "Type", "RunType"})
	if err := table.Bulk(items); err != nil {
		return fmt.Errorf("Error adding items to table: %w", err)
	}

	if err := table.Render(); err != nil {
		return fmt.Errorf("Error rendering table: %w", err)
	}

	return nil
}

func runSchema(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("you must specify an attestor to view the schema of. Use 'witness attestors' for a list of available attestors")
	} else if len(args) > 1 {
		return fmt.Errorf("you can only get one attestor schema at a time")
	}

	attestor, err := attestation.GetAttestor(args[0])
	if err != nil {
		return fmt.Errorf("Error getting attestor: %w", err)
	}

	schema := attestor.Schema()
	schemaJson, err := schema.MarshalJSON()
	if err != nil {
		return fmt.Errorf("Error marshalling JSON schema: %w", err)
	}

	var indented bytes.Buffer
	err = json.Indent(&indented, schemaJson, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JSON schema:", err)
		os.Exit(1)
	}

	fmt.Print(indented.String())

	return nil
}
