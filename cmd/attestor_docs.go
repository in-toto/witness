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

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/spf13/cobra"
)

func DocsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "docs [attestor]",
		Short:             "Show documentation for an attestor",
		Long:              "Display detailed documentation for a specific attestor including usage examples",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDocs(cmd.Context(), args)
		},
	}
	return cmd
}

func runDocs(ctx context.Context, args []string) error {
	if len(args) == 0 {
		// Show list of attestors with summaries
		return showAttestorSummaries()
	} else if len(args) > 1 {
		return fmt.Errorf("you can only get documentation for one attestor at a time")
	}

	attestor, err := attestation.GetAttestor(args[0])
	if err != nil {
		return fmt.Errorf("error getting attestor: %w", err)
	}

	// Check if attestor implements Documenter interface
	documenter, ok := attestor.(attestation.Documenter)
	if !ok {
		return fmt.Errorf("attestor %s does not have documentation available", args[0])
	}

	doc := documenter.Documentation()
	
	// Print documentation
	fmt.Printf("# %s Attestor\n\n", strings.Title(attestor.Name()))
	
	if doc.Summary != "" {
		fmt.Printf("## Summary\n%s\n\n", doc.Summary)
	}
	
	if len(doc.Usage) > 0 {
		fmt.Printf("## When to Use\n")
		for _, usage := range doc.Usage {
			fmt.Printf("- %s\n", usage)
		}
		fmt.Println()
	}
	
	if doc.Example != "" {
		fmt.Printf("## Example\n```bash\n%s\n```\n\n", doc.Example)
	}
	
	fmt.Printf("## Type\n%s\n\n", attestor.Type())
	fmt.Printf("## Run Type\n%s\n", attestor.RunType())

	return nil
}

func showAttestorSummaries() error {
	fmt.Println("# Available Attestors\n")
	
	entries := attestation.RegistrationEntries()
	hasDocumentation := false
	
	for _, entry := range entries {
		attestor := entry.Factory()
		
		// Check if attestor implements Documenter
		if documenter, ok := attestor.(attestation.Documenter); ok {
			hasDocumentation = true
			doc := documenter.Documentation()
			
			fmt.Printf("## %s\n", attestor.Name())
			if doc.Summary != "" {
				fmt.Printf("%s\n", doc.Summary)
			}
			fmt.Printf("Use: `witness attestors docs %s` for more information\n\n", attestor.Name())
		}
	}
	
	if !hasDocumentation {
		// Fallback to simple list if no attestors have documentation
		fmt.Println("No attestor documentation available. Use 'witness attestors list' to see available attestors.")
		return nil
	}
	
	return nil
}