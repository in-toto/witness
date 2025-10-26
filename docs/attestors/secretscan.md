# Secretscan Attestor
The secretscan attestor is a post-product attestor that scans attestations and products for secrets and other sensitive information. It helps prevent accidental secret leakage by detecting secrets and securely storing their cryptographic digests instead of the actual values.

## How It Works
The attestor uses [Gitleaks](https://github.com/zricethezav/gitleaks) to scan for secrets in:

1. Products generated during the attestation process
2. Attestations from other attestors that ran earlier in the pipeline
3. Environment variable values that match sensitive patterns:
   - Scans for actual values of sensitive environment variables that might have leaked into files or attestations
   - Checks both for direct values and encoded values of environment variables
   - Supports partial matching of sensitive environment variable values
   - Respects the user-defined sensitive environment variable configuration from the attestation context
4. Multi-layer encoded secrets:
   - Detects secrets hidden in base64, hex, or URL-encoded content
   - Can decode multiple layers of encoding (e.g., double base64-encoded secrets)
   - Tracks the encoding path for audit and forensic purposes

When secrets are found, they are recorded in a structured format with the actual secret replaced by a DigestSet containing cryptographic hashes of the secret using all configured hash algorithms from the attestation context.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/secretscan/attestor",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "findings": {
          "items": {
            "$ref": "#/$defs/Finding"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "findings"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Finding": {
      "properties": {
        "ruleId": {
          "type": "string"
        },
        "description": {
          "type": "string"
        },
        "location": {
          "type": "string"
        },
        "startLine": {
          "type": "integer"
        },
        "secret": {
          "$ref": "#/$defs/DigestSet"
        },
        "match": {
          "type": "string"
        },
        "entropy": {
          "type": "number"
        },
        "encodingPath": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "locationApproximate": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "ruleId",
        "description",
        "location",
        "startLine"
      ]
    }
  }
}
```

# SecretScan Attestor Examples

This section contains examples demonstrating the capabilities of the SecretScan attestor. You can find the demo script [here](https://github.com/in-toto/go-witness/blob/main/attestation/secretscan/examples/demo-encoded-secrets.sh)

## Demo Scripts

### `demo-encoded-secrets.sh`

This script demonstrates the multi-layer encoding detection capabilities of the secretscan attestor. It:

1. Creates test files with secrets in various encodings:
   - Plain text
   - Base64-encoded
   - Double base64-encoded
   - URL-encoded
   - Hex-encoded
   - Mixed encoding (base64 + URL)

2. Runs the witness CLI with the secretscan attestor on each file

3. Extracts and displays the findings from each attestation

### Running the Demo

```sh
# Make sure the script is executable
chmod +x demo-encoded-secrets.sh

# Run the demo
./demo-encoded-secrets.sh
```

## Additional Resources

For more information about the secretscan attestor, see the [main README](https://github.com/in-toto/go-witness/blob/main/attestation/secretscan/README.md) in the parent directory.
