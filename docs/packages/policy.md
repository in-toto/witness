# Policy Package

## Summary

Policy definition and verification for witness attestations

## Description

The policy package provides the core policy engine for witness, including:
- Policy structure definition with steps, functionaries, and attestations
- Certificate constraint validation for X.509-based trust
- Rego policy evaluation for attestation content
- Policy verification against collections of attestations
- Trust root and timestamp authority management

## Usage

- Define multi-step software supply chain policies
- Specify trusted functionaries who can perform each step
- Require specific attestations for each step
- Validate attestation content with Rego policies
- Establish trust roots for signature verification

## Examples

### Certificate Constraint

Define certificate constraints for a functionary

```go
functionary := Functionary{
	Type: "root",
	CertConstraint: CertConstraint{
		CommonName:    "*.example.com",
		Organizations: []string{"Example Corp"},
		Emails:        []string{"*@example.com"},
		Roots:         []string{"example-root-ca"},
	},
}
```

### Rego Policy

Add a Rego policy to validate attestation content

```go
attestation := Attestation{
	Type: "https://witness.dev/attestations/git/v0.1",
	RegoPolicies: []RegoPolicy{{
		Name: "clean-worktree",
		Module: []byte("package git\ndeny[msg] {\n\tinput.worktreeclean == false\n\tmsg := \"git worktree must be clean\"\n}"),
	}},
}
```

### Basic Policy

Create a basic two-step policy

```go
policy := Policy{
	Expires: metav1.Time{Time: time.Now().Add(365 * 24 * time.Hour)},
	Steps: map[string]Step{
		"build": {
			Name: "build",
			Functionaries: []Functionary{{
				Type:        "publickey",
				PublicKeyID: "build-key",
			}},
			Attestations: []Attestation{{
				Type: "https://witness.dev/attestations/git/v0.1",
			}},
		},
		"test": {
			Name: "test",
			ArtifactsFrom: []string{"build"},
			Functionaries: []Functionary{{
				Type:        "publickey",
				PublicKeyID: "test-key",
			}},
			Attestations: []Attestation{{
				Type: "https://witness.dev/attestations/junit/v0.1",
			}},
		},
	},
}
```

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/policy/documentation",
  "$ref": "#/$defs/Documentation",
  "$defs": {
    "Documentation": {
      "properties": {
        "summary": {
          "type": "string",
          "title": "Summary",
          "description": "Brief description of the package"
        },
        "description": {
          "type": "string",
          "title": "Description",
          "description": "Detailed description of the package functionality"
        },
        "usage": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "Usage",
          "description": "Common use cases and scenarios"
        },
        "examples": {
          "additionalProperties": {
            "$ref": "#/$defs/Example"
          },
          "type": "object",
          "title": "Examples",
          "description": "Code examples demonstrating package usage"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "summary",
        "description",
        "usage",
        "examples"
      ]
    },
    "Example": {
      "properties": {
        "description": {
          "type": "string",
          "title": "Description",
          "description": "What this example demonstrates"
        },
        "code": {
          "type": "string",
          "title": "Code",
          "description": "Example code snippet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "description",
        "code"
      ]
    }
  }
}
```
