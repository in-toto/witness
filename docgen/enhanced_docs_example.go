// Example enhancement to docgen/docs.go showing how to extract documentation from go-witness

package main

import (
	"bytes"
	"fmt"
	"text/template"
	
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

// AttestorDocTemplate is the template for generating attestor documentation
const AttestorDocTemplate = `# {{ .Name }} Attestor

{{ .Description }}

{{ if .LongDescription }}
## Overview

{{ .LongDescription }}
{{ end }}

## When to Use

{{ range .When }}
- {{ . }}
{{ end }}

{{ if .ConfigOptions }}
## Configuration

| Flag | Type | Default | Description |
|------|------|---------|-------------|
{{ range .ConfigOptions }}| --attestor-{{ $.ShortName }}-{{ .Flag }} | {{ .Type }} | {{ .Default }} | {{ .Description }} |
{{ end }}
{{ end }}

## Examples

{{ range .Examples }}
### {{ .Name }}

{{ .Description }}

` + "```bash\n{{ .Command }}\n```" + `

{{ if .Output }}
**Example Output:**

` + "```json\n{{ .Output }}\n```" + `
{{ end }}
{{ end }}

{{ if .Security }}
## Security Considerations

{{ range .Security }}
- {{ . }}
{{ end }}
{{ end }}

## Schema

` + "```json\n{{ .Schema }}\n```" + `
`

// EnhancedAttestorDoc combines documentation from multiple sources
type EnhancedAttestorDoc struct {
	Name            string
	ShortName       string
	Description     string
	LongDescription string
	When            []string
	Examples        []Example
	Security        []string
	ConfigOptions   []ConfigOption
	Schema          string
}

type Example struct {
	Name        string
	Description string
	Command     string
	Output      string
}

type ConfigOption struct {
	Flag        string
	Type        string
	Default     string
	Description string
}

// generateEnhancedAttestorDocs generates documentation by combining multiple sources
func generateEnhancedAttestorDocs(attestor attestation.Attestor, entry attestation.RegistrationEntry) (string, error) {
	doc := EnhancedAttestorDoc{
		Name:      entry.Name,
		ShortName: entry.Name, // This would be normalized (e.g., "git" from "Git")
	}

	// 1. Get basic description from registration
	doc.Description = fmt.Sprintf("The %s attestor %s", entry.Name, getBasicDescription(attestor))

	// 2. Extract rich schema documentation
	schema := jsonschema.Reflect(attestor)
	schemaJSON, _ := schema.MarshalJSON()
	doc.Schema = string(schemaJSON)

	// 3. If attestor implements Documenter interface, get additional docs
	if documenter, ok := attestor.(attestation.Documenter); ok {
		docs := documenter.Documentation()
		doc.Description = docs.Description
		doc.LongDescription = docs.LongDescription
		doc.When = docs.When
		doc.Security = docs.Security
		
		// Convert examples
		for _, ex := range docs.Examples {
			doc.Examples = append(doc.Examples, Example{
				Name:        ex.Name,
				Description: ex.Description,
				Command:     ex.Command,
				Output:      ex.Output,
			})
		}
	}

	// 4. If attestor implements ConfigDocumenter, get config options
	if configDoc, ok := attestor.(attestation.ConfigDocumenter); ok {
		options := configDoc.ConfigDocumentation()
		for _, opt := range options {
			doc.ConfigOptions = append(doc.ConfigOptions, ConfigOption{
				Flag:        opt.Flag,
				Type:        opt.Type,
				Default:     opt.Default,
				Description: opt.Description,
			})
		}
	}

	// 5. Generate markdown using template
	tmpl, err := template.New("attestor").Parse(AttestorDocTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, doc); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// getBasicDescription would extract a basic description from the attestor type
func getBasicDescription(attestor attestation.Attestor) string {
	// This could use reflection or type switches to provide basic descriptions
	// when the Documenter interface isn't implemented
	return "provides attestation functionality"
}

// Example of how this would be integrated into the existing docgen
func enhancedGenerateAttestorDocs() error {
	for _, entry := range attestation.RegistrationEntries() {
		attestor := entry.Factory()
		
		// Generate enhanced documentation
		markdown, err := generateEnhancedAttestorDocs(attestor, entry)
		if err != nil {
			return fmt.Errorf("failed to generate docs for %s: %w", entry.Name, err)
		}
		
		// Write to file
		filename := fmt.Sprintf("docs/attestors/%s.md", entry.Name)
		if err := writeFile(filename, markdown); err != nil {
			return fmt.Errorf("failed to write docs for %s: %w", entry.Name, err)
		}
	}
	
	return nil
}

// Interfaces that would be added to go-witness
type Documenter interface {
	Documentation() AttestorDocumentation
}

type ConfigDocumenter interface {
	ConfigDocumentation() []ConfigOptionDoc
}

type AttestorDocumentation struct {
	Name            string
	Description     string
	LongDescription string
	When            []string
	Examples        []ExampleDoc
	Security        []string
}

type ExampleDoc struct {
	Name        string
	Description string
	Command     string
	Output      string
}

type ConfigOptionDoc struct {
	Flag        string
	Type        string
	Default     string
	Description string
}

// Stub for writeFile
func writeFile(filename, content string) error {
	// Implementation would write the file
	return nil
}