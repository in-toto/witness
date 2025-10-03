# Proposal: Attestor Documentation in go-witness

## Overview

Move attestor documentation to live alongside the code in go-witness, using idiomatic Go patterns for extraction into the witness CLI documentation.

## Recommended Approach

### 1. Enhanced Struct Tags with JSON Schema

Add rich documentation to attestor structs using `jsonschema` tags:

```go
// in go-witness attestation/git/git.go
type Attestor struct {
    // Status captures the current state of the git repository
    Status GitStatus `json:"status" jsonschema:"title=Repository Status,description=Current state of git repository including modified files and branch information"`
    
    // CommitHash is the SHA of the current commit
    CommitHash string `json:"commithash" jsonschema:"title=Commit Hash,description=SHA hash of the current HEAD commit,example=a1b2c3d4e5f6"`
}
```

### 2. Documentation Interface

Add a `Documenter` interface that attestors can implement:

```go
// in go-witness attestation/attestor.go
type Documenter interface {
    // Documentation returns structured documentation for the attestor
    Documentation() AttestorDocumentation
}

type AttestorDocumentation struct {
    Name        string
    Description string
    LongDescription string
    When        []string // When to use this attestor
    Examples    []Example
    Security    []string // Security considerations
}

type Example struct {
    Name        string
    Description string
    Command     string
    Output      string // Example output
}
```

### 3. Implement Documentation Method

Each attestor implements the interface:

```go
// in go-witness attestation/git/git.go
func (a *Attestor) Documentation() attestation.AttestorDocumentation {
    return attestation.AttestorDocumentation{
        Name: "Git",
        Description: "Captures comprehensive Git repository state",
        LongDescription: `The Git attestor records the complete state of a git repository...`,
        When: []string{
            "Source code provenance for any git-based project",
            "Verifying builds from specific commits/branches",
            "Detecting uncommitted changes in builds",
        },
        Examples: []attestation.Example{
            {
                Name: "Basic Usage",
                Description: "Capture git state during build",
                Command: "witness run -a git -s build -- go build ./...",
                Output: `{
                    "type": "https://witness.io/attestations/git/v0.1",
                    "attestation": {
                        "commithash": "a1b2c3d4..."
                    }
                }`,
            },
        },
        Security: []string{
            "May expose sensitive branch names or commit messages",
            "Consider filtering in public CI/CD environments",
        },
    }
}
```

### 4. Embedded Documentation Files

For complex documentation, use Go's embed directive:

```go
//go:embed docs/git-attestor.md
var gitAttestorDocs string

//go:embed docs/examples/*
var examples embed.FS
```

### 5. Schema Generation Enhancement

Leverage the existing schema generation with enhanced documentation:

```go
// Enhanced schema generation in witness CLI
func generateAttestorDocs(attestor attestation.Attestor) {
    // Get schema with rich descriptions
    schema := jsonschema.Reflect(attestor)
    
    // If attestor implements Documenter, get additional docs
    if doc, ok := attestor.(attestation.Documenter); ok {
        docs := doc.Documentation()
        // Merge with schema documentation
    }
}
```

### 6. CLI Integration

Update witness CLI to access documentation at runtime:

```bash
# New command to show attestor documentation
witness attestor docs git

# Enhanced help for attestors
witness run --help-attestor git
```

## Implementation Plan

### Phase 1: Struct Tag Enhancement
1. Add `jsonschema` tags to all attestor structs in go-witness
2. Include descriptions, examples, and constraints
3. Update schema generation to use these tags

### Phase 2: Documentation Interface
1. Define `Documenter` interface in go-witness
2. Implement for each attestor
3. Include examples and security considerations

### Phase 3: CLI Integration
1. Update docgen to pull from go-witness documentation
2. Add runtime documentation commands
3. Generate markdown from structured documentation

### Phase 4: Automation
1. Use `go generate` to extract documentation
2. Create templates for consistent formatting
3. Set up CI to verify documentation completeness

## Example Implementation

Here's a complete example for the Git attestor:

```go
// attestation/git/git.go
package git

import (
    _ "embed"
    "github.com/in-toto/go-witness/attestation"
)

//go:embed docs/description.md
var longDescription string

type Attestor struct {
    Status     GitStatus `json:"status" jsonschema:"title=Repository Status,description=Current git repository state"`
    CommitHash string    `json:"commithash" jsonschema:"title=Commit Hash,description=SHA of current HEAD,pattern=^[a-f0-9]{40}$"`
}

func (a *Attestor) Documentation() attestation.AttestorDocumentation {
    return attestation.AttestorDocumentation{
        Name:            "Git",
        Description:     "Captures comprehensive Git repository state",
        LongDescription: longDescription,
        When: []string{
            "Source code provenance for git-based projects",
            "Verifying builds from specific commits",
            "Detecting uncommitted changes",
        },
        Examples: []attestation.Example{
            {
                Name:        "Basic Usage",
                Description: "Capture git state during build",
                Command:     "witness run -a git -s build -- make",
            },
        },
    }
}

// Configuration documentation
func (a *Attestor) ConfigDocumentation() []attestation.ConfigOption {
    return []attestation.ConfigOption{
        {
            Flag:        "git-remote-url",
            Type:        "string",
            Description: "Override detected remote URL",
            Default:     "auto-detect",
        },
    }
}
```

## Benefits

1. **Single Source of Truth**: Documentation lives with code
2. **Type Safety**: Compile-time checking of documentation
3. **IDE Support**: Struct tags provide inline documentation
4. **Automated Generation**: Reduces manual maintenance
5. **Runtime Access**: CLI can show help dynamically
6. **Versioning**: Documentation versioned with code

## Migration Strategy

1. Start with one attestor (e.g., Git) as proof of concept
2. Implement interfaces and tooling
3. Gradually migrate other attestors
4. Update witness CLI docgen to use new system
5. Deprecate manual documentation files

## Similar Patterns in Go Ecosystem

- **Cobra**: Uses struct tags and methods for command documentation
- **Kong**: Embeds help in struct tags
- **Terraform**: Uses go:generate with templates
- **Kubernetes**: Uses marker comments for API documentation

This approach follows Go idioms while providing rich, maintainable documentation that can be extracted and used by the witness CLI.