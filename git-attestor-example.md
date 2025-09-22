# Git Attestor Documentation Example

## 1. Current State in go-witness

```go
// go-witness/attestation/git/git.go (current)
package git

type Attestor struct {
    CommitHash string `json:"commithash"`
    Committer  struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    } `json:"committer"`
    Status string `json:"status"`
}
```

## 2. Enhanced with jsonschema tags

```go
// go-witness/attestation/git/git.go (enhanced)
package git

type Attestor struct {
    CommitHash string `json:"commithash" jsonschema:"title=Commit Hash,description=SHA hash of the current HEAD commit,example=d3adb33f,pattern=^[a-f0-9]{40}$"`
    
    Committer struct {
        Name  string `json:"name" jsonschema:"title=Name,description=Full name of the person who committed,example=Jane Developer"`
        Email string `json:"email" jsonschema:"title=Email,description=Email address of the committer,example=jane@example.com,format=email"`
    } `json:"committer" jsonschema:"title=Committer,description=Information about who created this commit"`
    
    Status string `json:"status" jsonschema:"title=Repository Status,description=Whether the repository has uncommitted changes,enum=clean;dirty"`
    
    Branches []string `json:"branches" jsonschema:"title=Branches,description=List of branches containing this commit,example=[main,develop]"`
    
    RemoteURL string `json:"remoteurl" jsonschema:"title=Remote URL,description=URL of the git remote origin,example=https://github.com/in-toto/witness.git"`
}

// Additional documentation constants
const (
    Name = "git"
    Description = "Records comprehensive git repository state including commit information, branches, tags, and working directory status"
    
    // When to use
    Usage1 = "Establishing source code provenance for any git-based project"
    Usage2 = "Ensuring builds are from specific commits or branches" 
    Usage3 = "Detecting uncommitted changes that could affect build reproducibility"
    Usage4 = "Tracking which version of code was used in a build"
    
    // Examples
    Example1Desc = "Basic usage during a build"
    Example1Cmd = "witness run -a git -s build -- make build"
    
    Example2Desc = "Using with multiple attestors"
    Example2Cmd = "witness run -a git,environment,slsa -s build -- go build ./..."
    
    // Security notes
    SecurityNote1 = "Repository URLs may contain sensitive information or access tokens"
    SecurityNote2 = "Commit messages might contain sensitive data"
    SecurityNote3 = "Branch names could reveal internal project information"
)
```

## 3. Generated JSON Schema (automatic)

The `jsonschema.Reflect()` function would now generate:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "commithash": {
      "type": "string",
      "title": "Commit Hash",
      "description": "SHA hash of the current HEAD commit",
      "example": "d3adb33f",
      "pattern": "^[a-f0-9]{40}$"
    },
    "committer": {
      "type": "object",
      "title": "Committer",
      "description": "Information about who created this commit",
      "properties": {
        "name": {
          "type": "string",
          "title": "Name",
          "description": "Full name of the person who committed",
          "example": "Jane Developer"
        },
        "email": {
          "type": "string",
          "title": "Email",
          "description": "Email address of the committer",
          "example": "jane@example.com",
          "format": "email"
        }
      }
    },
    "status": {
      "type": "string",
      "title": "Repository Status",
      "description": "Whether the repository has uncommitted changes",
      "enum": ["clean", "dirty"]
    },
    "branches": {
      "type": "array",
      "title": "Branches",
      "description": "List of branches containing this commit",
      "example": ["main", "develop"],
      "items": {
        "type": "string"
      }
    },
    "remoteurl": {
      "type": "string",
      "title": "Remote URL",
      "description": "URL of the git remote origin",
      "example": "https://github.com/in-toto/witness.git"
    }
  }
}
```

## 4. Enhanced docgen in witness CLI

```go
// witness/docgen/docs.go (enhanced section)
func generateGitAttestorDocs() {
    // Get the attestor
    attestor := git.New()
    
    // Get enriched schema (this already works with current jsonschema tags!)
    schema := jsonschema.Reflect(attestor)
    schemaJSON, _ := json.MarshalIndent(schema, "", "  ")
    
    // Extract field documentation from schema
    fieldDocs := extractFieldDocs(schema)
    
    // Generate the markdown
    markdown := fmt.Sprintf(`# Git Attestor

%s

## When to Use

- %s
- %s
- %s
- %s

## Configuration

| Field | Type | Description | Example |
|-------|------|-------------|---------|
%s

## Examples

### %s
` + "```bash\n%s\n```" + `

### %s
` + "```bash\n%s\n```" + `

## Security Considerations

- %s
- %s
- %s

## Schema

` + "```json\n%s\n```",
        git.Description,
        git.Usage1, git.Usage2, git.Usage3, git.Usage4,
        formatFieldDocsTable(fieldDocs),
        git.Example1Desc, git.Example1Cmd,
        git.Example2Desc, git.Example2Cmd,
        git.SecurityNote1, git.SecurityNote2, git.SecurityNote3,
        string(schemaJSON),
    )
    
    // Write to file
    os.WriteFile("docs/attestors/git.md", []byte(markdown), 0644)
}
```

## 5. Generated Documentation (docs/attestors/git.md)

```markdown
# Git Attestor

Records comprehensive git repository state including commit information, branches, tags, and working directory status

## When to Use

- Establishing source code provenance for any git-based project
- Ensuring builds are from specific commits or branches
- Detecting uncommitted changes that could affect build reproducibility
- Tracking which version of code was used in a build

## Configuration

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| commithash | string | SHA hash of the current HEAD commit | d3adb33f |
| committer.name | string | Full name of the person who committed | Jane Developer |
| committer.email | string | Email address of the committer | jane@example.com |
| status | string | Whether the repository has uncommitted changes | clean |
| branches | array | List of branches containing this commit | [main, develop] |
| remoteurl | string | URL of the git remote origin | https://github.com/in-toto/witness.git |

## Examples

### Basic usage during a build
```bash
witness run -a git -s build -- make build
```

### Using with multiple attestors
```bash
witness run -a git,environment,slsa -s build -- go build ./...
```

## Security Considerations

- Repository URLs may contain sensitive information or access tokens
- Commit messages might contain sensitive data
- Branch names could reveal internal project information

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "commithash": {
      "type": "string",
      "title": "Commit Hash",
      "description": "SHA hash of the current HEAD commit",
      "example": "d3adb33f",
      "pattern": "^[a-f0-9]{40}$"
    },
    ...
  }
}
```
```

## 6. CLI Help Integration

```bash
# New capability: attestor-specific help
$ witness run --help-attestor git

Git Attestor
Records comprehensive git repository state including commit information, branches, tags, and working directory status

WHEN TO USE:
  • Establishing source code provenance for any git-based project
  • Ensuring builds are from specific commits or branches
  • Detecting uncommitted changes that could affect build reproducibility

FIELDS:
  commithash    SHA hash of the current HEAD commit (e.g., d3adb33f)
  committer     Information about who created this commit
    .name       Full name of the person who committed
    .email      Email address of the committer
  status        Whether the repository has uncommitted changes (clean/dirty)
  branches      List of branches containing this commit
  remoteurl     URL of the git remote origin

EXAMPLE:
  witness run -a git -s build -- make build

SECURITY NOTES:
  ⚠ Repository URLs may contain sensitive information or access tokens
  ⚠ Commit messages might contain sensitive data
```

## Benefits of This Approach

1. **Zero Breaking Changes**: Just adding struct tags doesn't change any behavior
2. **Immediate IDE Support**: Developers see descriptions when hovering over fields
3. **Works Today**: The jsonschema library already supports these tags
4. **Progressive Enhancement**: Can update one field at a time
5. **Validation Built-in**: Pattern, format, and enum tags provide validation
6. **Examples in Schema**: The example tags show up in the generated schema

This is the most practical approach because it requires minimal changes to go-witness (just adding struct tags) while providing maximum documentation value.