# Secret Scan Attestor

The Secret Scan Attestor detects and records potential secrets, credentials, and sensitive information in files using Gitleaks pattern matching. It scans the working directory for hardcoded secrets and returns findings with metadata about detected secrets. Detected secrets are hashed rather than stored in plaintext for security.

## Use Cases

- CI/CD security scanning to prevent credential leaks before code is committed
- Compliance audits requiring evidence of secret detection controls
- Supply chain security validation ensuring no embedded credentials in artifacts
- Pre-commit hooks for detecting accidentally committed API keys or passwords

## Usage

```bash
witness run --step build -a secretscan -o attestation.json -- make build
```

With custom Gitleaks configuration:
```bash
witness run --step build -a secretscan --attestor-secretscan-config-path .gitleaks.toml -- make build
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--attestor-secretscan-config-path` | Built-in patterns | Path to custom Gitleaks configuration file for custom secret patterns |
| `--attestor-secretscan-fail-on-detection` | `false` | Fail the attestation process if secrets are detected |
| `--attestor-secretscan-max-decode-layers` | `3` | Maximum number of encoding layers to decode when searching for secrets (e.g., base64) |
| `--attestor-secretscan-max-file-size-mb` | `10` | Maximum file size to scan in megabytes (files larger are skipped) |
| `--attestor-secretscan-allowlist-regex` | None | Regex pattern for content to ignore (can be specified multiple times) |
| `--attestor-secretscan-allowlist-stopword` | None | Specific string to ignore (can be specified multiple times) |

## Subjects

| Subject | Description |
| ------- | ----------- |
| Secret digests | SHA256 hashes of detected secrets (not plaintext values) to enable verification without exposing sensitive data |

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
