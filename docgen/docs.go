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

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/in-toto/witness/cmd"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra/doc"

	_ "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/archivista"
)

var directory string

func init() {
	flag.StringVar(&directory, "dir", "docs", "Directory to store the generated docs")
	flag.Parse()
}

// PackageDocumentation represents the documentation structure for packages
type PackageDocumentation interface {
	GetSummary() string
	GetDescription() string
	GetUsage() []string
	GetExamples() map[string]struct {
		Description string
		Code        string
	}
}

// Helper function to generate package documentation using actual Documentation types
func generatePackageDoc(packageName string, doc interface{}, outputDir string) {
	// Create markdown content
	content := fmt.Sprintf("# %s Package\n\n", strings.Title(packageName))
	
	// Try to get documentation fields using type assertion
	switch d := doc.(type) {
	case cryptoutil.Documentation:
		content += formatDocumentationContent(d.Summary, d.Description, d.Usage)
		content += formatCryptoutilExamples(d.Examples)
	case policy.Documentation:
		content += formatDocumentationContent(d.Summary, d.Description, d.Usage)
		content += formatPolicyExamples(d.Examples)
	case signer.Documentation:
		content += formatDocumentationContent(d.Summary, d.Description, d.Usage)
		content += formatSignerExamples(d.Examples)
		// Add provider documentation if available
		if len(d.Providers) > 0 {
			content += "## Available Providers\n\n"
			for name, provider := range d.Providers {
				content += fmt.Sprintf("### %s\n\n%s\n\n", name, provider.Summary)
				if len(provider.Options) > 0 {
					content += "**Options:**\n"
					for opt, desc := range provider.Options {
						content += fmt.Sprintf("- `%s`: %s\n", opt, desc)
					}
					content += "\n"
				}
				if provider.Example != "" {
					content += fmt.Sprintf("**Example:**\n```bash\n%s\n```\n\n", provider.Example)
				}
			}
		}
	case dsse.Documentation:
		content += formatDocumentationContent(d.Summary, d.Description, d.Usage)
		content += formatDsseExamples(d.Examples)
	case archivista.Documentation:
		content += formatDocumentationContent(d.Summary, d.Description, d.Usage)
		content += formatArchivistaExamples(d.Examples)
	default:
		log.Printf("Unknown documentation type for %s", packageName)
		return
	}
	
	// Generate JSON schema
	schema := jsonschema.Reflect(doc)
	schemaJson, err := schema.MarshalJSON()
	if err != nil {
		log.Printf("Error marshalling JSON schema for %s: %v", packageName, err)
		return
	}
	
	var indented bytes.Buffer
	err = json.Indent(&indented, schemaJson, "", "  ")
	if err != nil {
		log.Printf("Error formatting JSON schema for %s: %v", packageName, err)
		return
	}
	
	content += fmt.Sprintf("## Schema\n\n```json\n%s\n```\n", indented.String())
	
	// Write markdown file
	mdPath := fmt.Sprintf("%s/%s.md", outputDir, packageName)
	err = os.WriteFile(mdPath, []byte(content), 0644)
	if err != nil {
		log.Printf("Error writing documentation for %s: %v", packageName, err)
		return
	}
	
	// Write JSON schema file
	jsonPath := fmt.Sprintf("%s/%s.json", outputDir, packageName)
	err = os.WriteFile(jsonPath, indented.Bytes(), 0644)
	if err != nil {
		log.Printf("Error writing schema for %s: %v", packageName, err)
		return
	}
	
	log.Printf("Documentation for %s written to %s", packageName, mdPath)
}

// Helper to format documentation content consistently
func formatDocumentationContent(summary, description string, usage []string) string {
	content := ""
	
	if summary != "" {
		content += fmt.Sprintf("## Summary\n\n%s\n\n", summary)
	}
	
	if description != "" {
		content += fmt.Sprintf("## Description\n\n%s\n\n", description)
	}
	
	if len(usage) > 0 {
		content += "## Usage\n\n"
		for _, u := range usage {
			content += fmt.Sprintf("- %s\n", u)
		}
		content += "\n"
	}
	
	return content
}

// Format examples for each package type
func formatCryptoutilExamples(examples map[string]cryptoutil.Example) string {
	if len(examples) == 0 {
		return ""
	}
	content := "## Examples\n\n"
	for name, example := range examples {
		content += fmt.Sprintf("### %s\n\n", strings.Title(strings.ReplaceAll(name, "_", " ")))
		content += fmt.Sprintf("%s\n\n```go\n%s\n```\n\n", example.Description, example.Code)
	}
	return content
}

func formatPolicyExamples(examples map[string]policy.Example) string {
	if len(examples) == 0 {
		return ""
	}
	content := "## Examples\n\n"
	for name, example := range examples {
		content += fmt.Sprintf("### %s\n\n", strings.Title(strings.ReplaceAll(name, "_", " ")))
		content += fmt.Sprintf("%s\n\n```go\n%s\n```\n\n", example.Description, example.Code)
	}
	return content
}

func formatSignerExamples(examples map[string]signer.Example) string {
	if len(examples) == 0 {
		return ""
	}
	content := "## Examples\n\n"
	for name, example := range examples {
		content += fmt.Sprintf("### %s\n\n", strings.Title(strings.ReplaceAll(name, "_", " ")))
		content += fmt.Sprintf("%s\n\n```go\n%s\n```\n\n", example.Description, example.Code)
	}
	return content
}

func formatDsseExamples(examples map[string]dsse.Example) string {
	if len(examples) == 0 {
		return ""
	}
	content := "## Examples\n\n"
	for name, example := range examples {
		content += fmt.Sprintf("### %s\n\n", strings.Title(strings.ReplaceAll(name, "_", " ")))
		content += fmt.Sprintf("%s\n\n```go\n%s\n```\n\n", example.Description, example.Code)
	}
	return content
}

func formatArchivistaExamples(examples map[string]archivista.Example) string {
	if len(examples) == 0 {
		return ""
	}
	content := "## Examples\n\n"
	for name, example := range examples {
		content += fmt.Sprintf("### %s\n\n", strings.Title(strings.ReplaceAll(name, "_", " ")))
		content += fmt.Sprintf("%s\n\n```go\n%s\n```\n\n", example.Description, example.Code)
	}
	return content
}

func main() {
	log.Println("Generating CLI Reference documentation")
	mdContent := "# Witness CLI Reference\n\nThis is the reference for the Witness command line tool, generated by [Cobra](https://cobra.dev/).\n\n"
	// Generate markdown content for all commands
	for _, command := range cmd.New().Commands() {
		// We are not generating docs for the completion command right now, as it doesn't render in Markdown correctly
		if command.Use == "completion [bash|zsh|fish|powershell]" {
			continue
		}

		buf := new(bytes.Buffer)
		err := doc.GenMarkdown(command, buf)
		if err != nil {
			fmt.Println("Error generating markdown for command:", command.Use)
			continue
		}
		mdContent += buf.String()
	}

	// Write the combined markdown content to a file
	err := os.WriteFile(fmt.Sprintf("%s/commands.md", directory), []byte(mdContent), 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		os.Exit(1)
	}

	log.Println("Documentation generated successfully")

	entries := attestation.RegistrationEntries()
	for _, entry := range entries {
		att := entry.Factory()
		
		// Generate enhanced documentation if attestor implements Documenter
		enhancedDoc := ""
		if documenter, ok := att.(attestation.Documenter); ok {
			doc := documenter.Documentation()
			if doc.Summary != "" {
				enhancedDoc += "\n## Summary\n\n" + doc.Summary + "\n\n"
			}
			if len(doc.Usage) > 0 {
				enhancedDoc += "## When to Use\n\n"
				for _, usage := range doc.Usage {
					enhancedDoc += "- " + usage + "\n"
				}
				enhancedDoc += "\n"
			}
			if doc.Example != "" {
				enhancedDoc += "## Example\n\n```bash\n" + doc.Example + "\n```\n\n"
			}
		}
		
		schema := att.Schema()
		schemaJson, err := schema.MarshalJSON()
		if err != nil {
			fmt.Println("Error marshalling JSON schema:", err)
			os.Exit(1)
		}

		var indented bytes.Buffer
		err = json.Indent(&indented, schemaJson, "", "  ")
		if err != nil {
			fmt.Println("Error marshalling JSON schema:", err)
			os.Exit(1)
		}

		schemaContent := "## Schema" + "\n```json\n" + indented.String() + "\n```\n"
		err = os.WriteFile(fmt.Sprintf("%s/attestors/%s.json", directory, att.Name()), []byte(indented.String()+"\n "), 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}
		log.Printf("Schema for %s written to %s/attestors/%s.json\n", att.Name(), directory, att.Name())
		f, err := os.ReadFile(fmt.Sprintf("%s/attestors/%s.md", directory, att.Name()))
		if err != nil {
			fmt.Println("Error reading file:", err)
			os.Exit(1)
		}

		// Find the index of "## Schema" string
		index := strings.Index(string(f), "## Schema")
		if index == -1 {
			// If no schema section exists, add enhanced doc and schema
			f = append(f, []byte(enhancedDoc)...)
			f = append(f, schemaContent...)

			err = os.WriteFile(fmt.Sprintf("%s/attestors/%s.md", directory, att.Name()), f, 0644)
			if err != nil {
				fmt.Println("Error writing to file:", err)
				os.Exit(1)
			}
			continue
		}

		// Replace existing schema section
		before := f[:index]
		f = append(before, schemaContent...)

		err = os.WriteFile(fmt.Sprintf("%s/attestors/%s.md", directory, att.Name()), f, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}

		log.Printf("Schema for %s written to %s/attestors/%s.md\n", att.Name(), directory, att.Name())

	}

	log.Println("Generating schema for the Witness Collection")
	coll := jsonschema.Reflect(attestation.Collection{})
	schemaJson, err := coll.MarshalJSON()
	if err != nil {
		fmt.Println("Error marshalling JSON schema:", err)
		os.Exit(1)
	}
	var indented bytes.Buffer
	err = json.Indent(&indented, schemaJson, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling JSON schema:", err)
		os.Exit(1)
	}
	schemaContent := "## Schema" + "\n```json\n" + indented.String() + "\n```\n"
	f, err := os.ReadFile(fmt.Sprintf("%s/concepts/collection.md", directory))
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	// Find the index of "## Schema" string
	index := strings.Index(string(f), "## Schema")
	if index == -1 {
		f = append(f, schemaContent...)

		err = os.WriteFile(fmt.Sprintf("%s/concepts/collection.md", directory), f, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}
	} else {

		// Replace existing schema section
		before := f[:index]
		f = append(before, schemaContent...)

		err = os.WriteFile(fmt.Sprintf("%s/concepts/collection.md", directory), f, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			os.Exit(1)
		}

		log.Printf("Schema for collection written to %s/concepts/collection.md\n", directory)
	}

	// Generate documentation for core packages
	log.Println("Generating documentation for core packages")
	
	// Create packages directory if it doesn't exist
	packagesDir := fmt.Sprintf("%s/packages", directory)
	if err := os.MkdirAll(packagesDir, 0755); err != nil {
		fmt.Println("Error creating packages directory:", err)
		os.Exit(1)
	}

	// Generate documentation for each package
	generatePackageDoc("cryptoutil", cryptoutil.PackageDocumentation(), packagesDir)
	generatePackageDoc("policy", policy.PackageDocumentation(), packagesDir)
	generatePackageDoc("signer", signer.PackageDocumentation(), packagesDir)
	generatePackageDoc("dsse", dsse.PackageDocumentation(), packagesDir)
	generatePackageDoc("archivista", archivista.PackageDocumentation(), packagesDir)
}
