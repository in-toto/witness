# Policy Verify (Verification Summary) Attestor

The Policy Verify Attestor generates a [verification summary attestation](https://slsa.dev/spec/v1.0/verification_summary) for `witness verify` invocations, providing information about the verification that took place.

**NOTE:** This attestor cannot be used during `witness run` (e.g., `witness run --attestors policyverify`).

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "verifier": {
          "$ref": "#/$defs/Verifier"
        },
        "timeVerified": {
          "type": "string",
          "format": "date-time"
        },
        "policy": {
          "$ref": "#/$defs/ResourceDescriptor"
        },
        "inputAttestations": {
          "items": {
            "$ref": "#/$defs/ResourceDescriptor"
          },
          "type": "array"
        },
        "verificationResult": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "verifier",
        "timeVerified",
        "policy",
        "inputAttestations",
        "verificationResult"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "ResourceDescriptor": {
      "properties": {
        "uri": {
          "type": "string"
        },
        "digest": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "uri",
        "digest"
      ]
    },
    "Verifier": {
      "properties": {
        "id": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "id"
      ]
    }
  }
}
```
