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
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/attestation"
)

// ShowAttestorHelp displays help for a specific attestor
func ShowAttestorHelp(attestorName string) error {
	attestor, err := attestation.GetAttestor(attestorName)
	if err != nil {
		return fmt.Errorf("unknown attestor: %s", attestorName)
	}

	// Check if attestor implements Documenter interface
	documenter, ok := attestor.(attestation.Documenter)
	if !ok {
		// Fallback to basic information
		fmt.Printf("\n%s Attestor\n", strings.Title(attestor.Name()))
		fmt.Printf("Type: %s\n", attestor.Type())
		fmt.Printf("Run Type: %s\n\n", attestor.RunType())
		fmt.Println("No additional documentation available for this attestor.")
		return nil
	}

	doc := documenter.Documentation()
	
	// Print help
	fmt.Printf("\n%s Attestor\n", strings.Title(attestor.Name()))
	fmt.Println(strings.Repeat("=", len(attestor.Name())+9))
	
	if doc.Summary != "" {
		fmt.Printf("\n%s\n", doc.Summary)
	}
	
	if len(doc.Usage) > 0 {
		fmt.Printf("\nWHEN TO USE:\n")
		for _, usage := range doc.Usage {
			fmt.Printf("  • %s\n", usage)
		}
	}
	
	if doc.Example != "" {
		fmt.Printf("\nEXAMPLE:\n  %s\n", doc.Example)
	}
	
	fmt.Printf("\nTYPE: %s\n", attestor.Type())
	fmt.Printf("RUN TYPE: %s\n", attestor.RunType())
	
	// Show attestor-specific flags
	fmt.Printf("\nATTESTOR FLAGS:\n")
	fmt.Printf("  See 'witness run --help' for attestor-specific flags starting with '--attestor-%s-'\n", attestor.Name())
	
	fmt.Printf("\nSEE ALSO:\n")
	fmt.Printf("  witness attestors list      List all available attestors\n")
	fmt.Printf("  witness attestors docs      Show documentation for all attestors\n")
	fmt.Printf("  witness attestors schema    Show JSON schema for an attestor\n")

	return nil
}