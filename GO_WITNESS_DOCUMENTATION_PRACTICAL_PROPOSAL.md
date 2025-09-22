# Practical Implementation: Enhanced Attestor Documentation

Based on analysis of the current go-witness codebase, here's a practical approach that builds on existing infrastructure.

## Current State

- ✅ Schema generation using `invopop/jsonschema`
- ✅ `docgen` tool that updates documentation
- ✅ Each attestor has `Schema()` method
- ❌ Limited use of jsonschema struct tags
- ❌ No field-level descriptions in schemas
- ❌ Configuration options documented separately

## Proposed Enhancement

### Step 1: Enrich Struct Tags (Minimal Change)

Add `jsonschema` tags to attestor structs in go-witness:

```go
// Before (current state)
type Attestor struct {
    CommitHash string `json:"commithash"`
    Status     string `json:"status"`
}

// After (enhanced)
type Attestor struct {
    CommitHash string `json:"commithash" jsonschema:"title=Commit Hash,description=SHA hash of the current HEAD commit,example=a1b2c3d4e5f6,pattern=^[a-f0-9]{40}$"`
    Status     string `json:"status" jsonschema:"title=Repository Status,description=Current state of the working directory (clean or dirty),enum=clean;dirty"`
}
```

### Step 2: Add Documentation Constants

For each attestor, add documentation constants in go-witness:

```go
// attestation/git/git.go
package git

const (
    // These constants can be extracted by docgen
    Description = "Captures comprehensive Git repository state including commit info, branch, tags, and working directory status"
    
    Use1 = "Source code provenance for any git-based project"
    Use2 = "Verifying builds from specific commits/branches"
    Use3 = "Detecting uncommitted changes in builds"
    
    Example1Command = "witness run -a git -s build -- go build ./..."
    Example1Description = "Capture git state during Go build"
    
    SecurityNote1 = "May expose sensitive branch names or commit messages"
    SecurityNote2 = "Consider repository visibility in public CI/CD environments"
)
```

### Step 3: Enhance Existing docgen

Update the witness CLI's `docgen/docs.go` to extract the enhanced information:

```go
// Modified version of existing generateAttestorDocs
func generateAttestorDocs() error {
    for _, e := range attestation.RegistrationEntries() {
        // Existing schema generation
        attestor := e.Factory()
        schema := attestor.Schema()
        
        // NEW: Extract enhanced schema with descriptions
        enhancedSchema := jsonschema.Reflect(attestor)
        
        // NEW: Extract documentation constants using reflection
        docs := extractDocumentationConstants(e.Name)
        
        // Generate enhanced markdown
        markdown := generateEnhancedMarkdown(e.Name, enhancedSchema, docs)
        
        // Write files as before
    }
}

// Extract constants from go-witness package
func extractDocumentationConstants(attestorName string) AttestorDocs {
    // Use go/ast to parse the attestor package and extract constants
    // Or use go generate to create a documentation registry
}
```

### Step 4: Progressive Migration

1. **Phase 1**: Add jsonschema tags to one attestor (e.g., git)
2. **Phase 2**: Update docgen to use enhanced schemas
3. **Phase 3**: Add documentation constants
4. **Phase 4**: Migrate remaining attestors

## Minimal Example Implementation

Here's what needs to change in go-witness for the git attestor:

```go
// go-witness: attestation/git/git.go
package git

// Documentation that can be extracted by tools
const (
    AttestorDescription = "Captures comprehensive Git repository state"
    AttestorUsageNote   = "Ideal for source code provenance tracking"
)

type Attestor struct {
    CommitHash string `json:"commithash" jsonschema:"title=Commit Hash,description=SHA of HEAD commit,pattern=^[a-f0-9]{40}$"`
    Author     Author `json:"author" jsonschema:"title=Commit Author,description=Person who authored the commit"`
    Status     Status `json:"status" jsonschema:"title=Repository Status,description=Working directory state"`
}

type Author struct {
    Name  string `json:"name" jsonschema:"title=Author Name,description=Full name of commit author,example=John Doe"`
    Email string `json:"email" jsonschema:"title=Author Email,description=Email address of commit author,example=john@example.com"`
}
```

## Witness CLI docgen Enhancement

```go
// witness: docgen/docs.go enhancement
func generateAttestorMarkdown(name string, schema *jsonschema.Schema) string {
    // Read existing markdown file
    existing := readExistingMarkdown(name)
    
    // Update schema section with enhanced schema
    updated := updateSchemaSection(existing, schema)
    
    // NEW: Add field documentation table
    fieldDocs := extractFieldDocumentation(schema)
    updated = addFieldDocumentationTable(updated, fieldDocs)
    
    return updated
}
```

## Benefits of This Approach

1. **Minimal Changes**: Works with existing infrastructure
2. **Backward Compatible**: Doesn't break existing documentation
3. **Progressive Enhancement**: Can be done incrementally
4. **IDE Support**: Developers see documentation in their IDE via struct tags
5. **Single Source of Truth**: Documentation lives with code

## Next Steps

1. **PR to go-witness**: Add jsonschema tags to one attestor as proof of concept
2. **PR to witness**: Enhance docgen to use rich schemas
3. **Gradual migration**: Update remaining attestors over time

## Alternative: go:generate Approach

If modifying attestor structs is too invasive, use go:generate:

```go
//go:generate go run github.com/in-toto/witness/docgen -attestor git

// +witness:doc title="Git Attestor"
// +witness:doc description="Captures comprehensive Git repository state"
// +witness:doc usage="Source code provenance tracking"
type Attestor struct {
    // +witness:field description="SHA of current HEAD commit"
    // +witness:field example="a1b2c3d4e5f6"
    CommitHash string `json:"commithash"`
}
```

This approach uses marker comments that can be extracted without modifying the structs themselves.