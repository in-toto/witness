# Cryptoutil Package

## Summary

Cryptographic utilities for digest calculation, signature verification, and key handling

## Description

The cryptoutil package provides core cryptographic functionality for witness, including:
- DigestSet: Calculate and manage multiple digests for files and data
- Signature creation and verification with multiple algorithms (RSA, ECDSA, ED25519)
- X.509 certificate handling and verification
- Git Object ID (gitoid) calculation
- Directory hashing compatible with Go module tooling

## Usage

- Calculate cryptographic digests of files and directories
- Create and verify digital signatures
- Handle X.509 certificates and public keys
- Generate attestation signatures with timestamp support
- Verify attestation signatures against policies

## Examples

### Create Signer

Create a signer from a private key

```go
// Load private key and create signer
keyPEM, _ := os.ReadFile("private.pem")
signer, err := NewSignerFromPEM(keyPEM)
if err != nil {
    log.Fatal(err)
}

message := []byte("data to sign")
signature, err := signer.Sign(bytes.NewReader(message))
```

### Calculate Digest

Calculate SHA256 digest of a file

```go
// Calculate digest of a file
hashes := []DigestValue{{Hash: crypto.SHA256}}
digestSet, err := CalculateDigestSetFromFile("myfile.txt", hashes)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("SHA256: %s\n", digestSet[DigestValue{Hash: crypto.SHA256}])
```

### Verify Signature

Verify a signature using a public key

```go
// Load public key and verify signature
pubKeyPEM, _ := os.ReadFile("public.pem")
verifier, err := NewVerifierFromPEM(pubKeyPEM)
if err != nil {
    log.Fatal(err)
}

message := []byte("hello world")
signature, _ := base64.StdEncoding.DecodeString("...")
err = verifier.Verify(message, signature)
```

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/cryptoutil/documentation",
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
