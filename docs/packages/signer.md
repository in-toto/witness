# Signer Package

## Summary

Extensible signing provider framework for witness attestations

## Description

The signer package provides a pluggable system for different signing mechanisms:
- File-based signing with local private keys
- Cloud KMS integration (AWS, GCP, Azure)
- Sigstore keyless signing with Fulcio
- SPIFFE/SPIRE workload identity signing
- HashiCorp Vault integration
- Extensible registry for custom providers

## Usage

- Sign attestations with various key management systems
- Abstract signing implementation from attestation logic
- Support both key-based and keyless signing workflows
- Enable workload identity-based signing in cloud environments
- Integrate with existing PKI infrastructure

## Examples

### Aws Kms

Use AWS KMS for signing

```go
// Create AWS KMS signer
provider, err := NewSignerProvider("kms",
    kms.WithRef("awskms:///arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
    kms.WithHash("SHA256"),
)

signer, err := provider.Signer(ctx)
```

### File Signer

Create a file-based signer

```go
// Create file signer
provider, err := NewSignerProvider("file",
    file.WithKeyPath("/path/to/private.key"),
    file.WithCertPath("/path/to/cert.pem"),
)
if err != nil {
    log.Fatal(err)
}

// Get signer
signer, err := provider.Signer(ctx)
if err != nil {
    log.Fatal(err)
}

// Sign data
signature, err := signer.Sign(bytes.NewReader(data))
```

### Fulcio Keyless

Use Sigstore keyless signing

```go
// Create Fulcio signer
provider, err := NewSignerProvider("fulcio",
    fulcio.WithFulcioURL("https://fulcio.sigstore.dev"),
    fulcio.WithOIDCIssuer("https://oauth2.sigstore.dev/auth"),
    fulcio.WithOIDCClientID("sigstore"),
)

// Get signer (will trigger OIDC flow)
signer, err := provider.Signer(ctx)
```

## Available Providers

### vault

HashiCorp Vault signing

**Options:**
- `token`: Vault authentication token
- `pki-path`: Path to PKI secrets engine
- `role`: PKI role name
- `url`: Vault server URL

**Example:**
```bash
witness run -s build --signer-vault-url https://vault.example.com --signer-vault-token s.abc123 -- make
```

### file

Signs with private keys stored in local files

**Options:**
- `key-path`: Path to private key file (PEM format)
- `cert-path`: Path to certificate file (optional)
- `intermediate-paths`: Paths to intermediate certificates (optional)

**Example:**
```bash
witness run -s build --signer-file-key-path key.pem -- make
```

### fulcio

Sigstore keyless signing using OIDC identity

**Options:**
- `fulcio-url`: Fulcio server URL
- `oidc-issuer`: OIDC token issuer URL
- `oidc-client-id`: OIDC client ID
- `token`: Pre-obtained OIDC token
- `token-path`: Path to file containing OIDC token

**Example:**
```bash
witness run -s build --signer-fulcio-url https://fulcio.sigstore.dev -- make
```

### kms

Cloud KMS signing (AWS, GCP, Azure)

**Options:**
- `ref`: KMS key reference URI
- `hash-algo`: Hash algorithm (SHA256, SHA384, SHA512)
- `key-version`: Specific key version to use

**Example:**
```bash
witness run -s build --signer-kms-ref gcpkms://projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey -- make
```

### spiffe

SPIFFE/SPIRE workload identity signing

**Options:**
- `socket-path`: Path to SPIFFE Workload API socket

**Example:**
```bash
witness run -s build --signer-spiffe-socket-path /tmp/spire-agent/public/api.sock -- make
```

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/signer/documentation",
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
        },
        "providers": {
          "additionalProperties": {
            "$ref": "#/$defs/ProviderDoc"
          },
          "type": "object",
          "title": "Providers",
          "description": "Documentation for available signer providers"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "summary",
        "description",
        "usage",
        "examples",
        "providers"
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
    },
    "ProviderDoc": {
      "properties": {
        "summary": {
          "type": "string",
          "title": "Summary",
          "description": "Brief description of the provider"
        },
        "options": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object",
          "title": "Options",
          "description": "Configuration options for this provider"
        },
        "example": {
          "type": "string",
          "title": "Example",
          "description": "Example usage of this provider"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "summary",
        "options",
        "example"
      ]
    }
  }
}
```
