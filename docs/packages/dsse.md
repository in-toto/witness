# Dsse Package

## Summary

Dead Simple Signing Envelope (DSSE) implementation for witness attestations

## Description

The dsse package implements the DSSE specification for creating and verifying signed envelopes:
- Create DSSE envelopes with multiple signatures
- Support for X.509 certificate chains in signatures
- RFC3161 timestamp integration
- Threshold signature verification
- Pre-authentication encoding per DSSE spec
- Compatible with in-toto attestation framework

## Usage

- Wrap attestations in signed DSSE envelopes
- Verify DSSE envelope signatures with threshold support
- Add trusted timestamps to signatures
- Include certificate chains for PKI verification
- Create portable signed attestation bundles

## Examples

### Create Envelope

Create a DSSE envelope with signature

```go
// Create payload
payload := []byte("{\"_type\": \"https://in-toto.io/Statement/v0.1\", \"subject\": [...]}")

// Sign with options
envelope, err := Sign("application/vnd.in-toto+json", payload, 
    WithSigner(signer),
    WithTimestampers(timestamper),
)
if err != nil {
    log.Fatal(err)
}

// Envelope now contains signed payload
```

### Verify Envelope

Verify a DSSE envelope with threshold

```go
// Define verifiers
verifiers := []cryptoutil.Verifier{verifier1, verifier2}

// Verify with threshold of 2
results, err := Verify(envelope, 
    WithVerifiers(verifiers...),
    WithThreshold(2),
    WithRoots(rootCerts),
)
if err != nil {
    log.Fatal(err)
}

// Check verification results
fmt.Printf("Passed verifiers: %d\n", len(results.PassedVerifiers))
```

### Add Timestamp

Add RFC3161 timestamp to signature

```go
// Create timestamper
timestamper := timestamp.NewRFC3161Timestamper(
    timestamp.WithUrl("https://freetsa.org/tsr"),
)

// Sign with timestamp
envelope, err := Sign(payloadType, payload,
    WithSigner(signer),
    WithTimestampers(timestamper),
)

// Envelope signatures now include timestamps
```

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/dsse/documentation",
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
