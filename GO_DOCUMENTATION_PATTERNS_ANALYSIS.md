# Idiomatic Go Documentation Patterns for Witness Attestors

## Executive Summary

This document analyzes idiomatic Go documentation patterns that can be used to document attestors in go-witness and extract that documentation into the witness CLI. Based on analysis of the codebase and industry best practices, I recommend implementing a multi-layered approach using Go struct tags, interface methods, and code generation.

## Current State Analysis

### Existing Infrastructure

1. **Documentation Generation**: Witness already has a `docgen` tool that:
   - Generates CLI command documentation using Cobra
   - Extracts JSON schemas from attestors using `invopop/jsonschema`
   - Updates attestor markdown files with schema information

2. **Attestor Registration**: Attestors use a factory pattern with:
   - `RegisterAttestation()` for registration
   - `Schema()` method returning `*jsonschema.Schema`
   - Type constants and metadata

3. **Documentation Files**: Each attestor has a corresponding `.md` file in `docs/attestors/`

## Recommended Documentation Patterns

### 1. Enhanced Struct Tags with jsonschema

The `invopop/jsonschema` library supports rich documentation through struct tags:

```go
type Attestor struct {
    CommitHash string `json:"commithash" jsonschema:"title=Git Commit Hash,description=The SHA1 hash of the current git commit,example=abc123def456"`
    Author     string `json:"author" jsonschema:"title=Author Name,description=The name of the commit author,example=John Doe"`
    AuthorEmail string `json:"authoremail" jsonschema:"title=Author Email,description=Email address of the commit author,format=email,example=john@example.com"`
    
    // Use unnamed fields for attestor-level documentation
    _ struct{} `jsonschema:"title=Git Attestor,description=Records the current state of git repository including commit information and file status"`
    _ struct{} `jsonschema:"additionalProperties=false"`
}
```

### 2. Documentation Interface Pattern

Create a documentation interface that attestors can implement:

```go
// in attestation/doc.go
type Documenter interface {
    // Short returns a one-line description
    Short() string
    
    // Long returns detailed documentation
    Long() string
    
    // Example returns example usage
    Example() string
    
    // When returns guidance on when to use this attestor
    When() []string
}

type ConfigDocumenter interface {
    // ConfigDocs returns documentation for configuration options
    ConfigDocs() []ConfigDoc
}

type ConfigDoc struct {
    Name        string
    Type        string
    Default     string
    Description string
    Example     string
}
```

Implementation example:

```go
func (a *Attestor) Short() string {
    return "Records git repository state including commits and file status"
}

func (a *Attestor) Long() string {
    return `The Git Attestor captures comprehensive information about the current 
state of a git repository, including:
- Current commit hash and metadata
- Author and committer information  
- Repository status (staged/unstaged files)
- Branch and tag information
- Remote repository URLs`
}

func (a *Attestor) Example() string {
    return `witness run -a git -s build -- make build`
}

func (a *Attestor) When() []string {
    return []string{
        "Tracking source code provenance",
        "Linking builds to specific commits",
        "Auditing code changes in CI/CD pipelines",
    }
}
```

### 3. Embed Documentation Files

Use Go 1.16+ embed directive to include documentation:

```go
package git

import _ "embed"

//go:embed doc.md
var documentation string

//go:embed examples/basic.yaml
var basicExample string

//go:embed examples/advanced.yaml  
var advancedExample string

func (a *Attestor) Documentation() string {
    return documentation
}

func (a *Attestor) Examples() map[string]string {
    return map[string]string{
        "basic":    basicExample,
        "advanced": advancedExample,
    }
}
```

### 4. Code Generation with go:generate

Enhance the existing docgen tool to extract documentation:

```go
//go:generate go run github.com/in-toto/witness/docgen -attestor-docs

// In each attestor file:
//go:generate go run ../../../docgen/attestor-doc-gen.go
```

The generator would:
1. Parse Go AST to extract struct tags
2. Call documentation methods if implemented
3. Generate markdown files
4. Update CLI help text

### 5. Runtime Documentation Access

Add documentation to the attestor registry:

```go
type AttestorEntry struct {
    Factory      FactoryFunc[Attestor]
    Options      []registry.Configurer
    Short        string
    Long         string
    Examples     []Example
    When         []string
}

func RegisterAttestationWithDocs(name, predicateType string, run RunType, 
    factory registry.FactoryFunc[Attestor], 
    docs AttestorDocs,
    opts ...registry.Configurer) {
    // Store documentation with registration
}
```

## Implementation Approach

### Phase 1: Struct Tag Enhancement

1. Add jsonschema tags to all attestor structs:
```go
// attestation/git/git.go
type Attestor struct {
    CommitHash string `json:"commithash" jsonschema:"title=Git Commit Hash,description=The SHA1 hash of the current git commit,example=abc123def456,required=true"`
    // ... other fields with documentation
}
```

2. Update docgen to extract and format these descriptions:
```go
// docgen/docs.go
func generateAttestorDocs(att attestation.Attestor) {
    schema := att.Schema()
    // Extract title, description, examples from schema
    // Generate markdown sections
}
```

### Phase 2: Documentation Interface

1. Define interfaces in attestation package:
```go
// attestation/doc.go
type Documenter interface {
    Documentation() Documentation
}

type Documentation struct {
    Short       string
    Long        string
    Examples    []Example
    When        []string
    Options     []OptionDoc
}
```

2. Implement for each attestor:
```go
func (a *Attestor) Documentation() attestation.Documentation {
    return attestation.Documentation{
        Short: "Records git repository state",
        // ...
    }
}
```

### Phase 3: CLI Integration

1. Update witness CLI to use documentation:
```go
// cmd/attestors.go
func attestorHelp(attestorName string) string {
    att, err := attestation.GetAttestor(attestorName)
    if err != nil {
        return ""
    }
    
    if doc, ok := att.(attestation.Documenter); ok {
        docs := doc.Documentation()
        return formatDocumentation(docs)
    }
    return ""
}
```

2. Add `witness attestor` subcommand:
```bash
witness attestor list              # List all attestors
witness attestor help git          # Show git attestor documentation  
witness attestor example git       # Show git attestor examples
```

### Phase 4: Code Generation Enhancement

Create a dedicated attestor documentation generator:

```go
// docgen/attestor-docs/main.go
package main

import (
    "go/ast"
    "go/parser"
    "go/token"
)

func generateAttestorDocs() {
    // Parse attestor Go files
    // Extract struct tags
    // Call documentation methods
    // Generate markdown
    // Update CLI help
}
```

## Best Practices from Other Projects

### Kubernetes Approach
- Uses godoc comments extensively
- Special markers for code generation (// +kubebuilder:...)
- Separate documentation generation tools (k8s-api-docgen)

### Terraform Approach  
- terraform-plugin-docs for provider documentation
- Templates with go text/template
- go:generate directives for automation
- Schema-driven documentation

### Docker Approach
- Embeds documentation in code
- Uses interfaces for plugin documentation
- Runtime documentation access

## Concrete Implementation Example

Here's a complete example for the Git attestor:

```go
// attestation/git/git.go
package git

import (
    _ "embed"
    "github.com/in-toto/go-witness/attestation"
    "github.com/invopop/jsonschema"
)

//go:embed README.md
var readmeDoc string

const (
    Name    = "git"
    Type    = "https://witness.dev/attestations/git/v0.1"
    RunType = attestation.PreMaterialRunType
)

// Attestor records the state of a git repository
type Attestor struct {
    // Git commit hash
    CommitHash string `json:"commithash" jsonschema:"title=Commit Hash,description=SHA1 hash of the current commit,example=abc123def456"`
    
    // Commit author name  
    Author string `json:"author" jsonschema:"title=Author,description=Name of the commit author,example=John Doe"`
    
    // Commit author email
    AuthorEmail string `json:"authoremail" jsonschema:"title=Author Email,description=Email of the commit author,format=email"`
    
    // Documentation metadata
    _ struct{} `jsonschema:"title=Git Attestor,description=Records git repository state including commits and status"`
}

// Documentation implements attestation.Documenter
func (a *Attestor) Documentation() attestation.Documentation {
    return attestation.Documentation{
        Short: "Records git repository state",
        Long:  readmeDoc,
        Examples: []attestation.Example{
            {
                Name: "Basic usage",
                Command: "witness run -a git -s build -- make",
                Description: "Capture git state before build",
            },
        },
        When: []string{
            "Tracking source code provenance",
            "Linking builds to commits",
            "Recording repository state in CI/CD",
        },
        Options: []attestation.OptionDoc{
            {
                Name: "git.fetch-tags",
                Type: "bool",
                Default: "false", 
                Description: "Fetch tags from remote before recording state",
            },
        },
    }
}
```

## Migration Path

1. **Week 1-2**: Add jsonschema tags to existing attestors
2. **Week 3-4**: Implement Documenter interface for all attestors  
3. **Week 5-6**: Update docgen to use new documentation
4. **Week 7-8**: Add CLI commands for runtime documentation access
5. **Week 9-10**: Implement advanced code generation
6. **Week 11-12**: Testing and documentation

## Benefits

1. **Single Source of Truth**: Documentation lives with code
2. **Type Safety**: Compile-time checking of documentation
3. **Automation**: Generated docs always in sync
4. **Runtime Access**: CLI can show help without external files
5. **IDE Support**: Documentation visible in code completion
6. **Standardization**: Consistent documentation format

## Conclusion

The recommended approach combines:
- **Immediate wins** through jsonschema struct tags
- **Structured documentation** via interfaces
- **Automation** through code generation
- **Runtime access** for better CLI UX

This provides a scalable, maintainable solution that follows Go idioms while meeting the specific needs of the Witness project.