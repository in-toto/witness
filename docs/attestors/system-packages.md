# system-packages Attestor

The System Packages attestor records the operating system and installed package information to verify the build environment’s state.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/system-packages/attestor",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "os": {
          "type": "string"
        },
        "distribution": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "packages": {
          "items": {
            "$ref": "#/$defs/Package"
          },
          "type": "array"
        },
        "digest": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "os",
        "distribution",
        "version",
        "packages",
        "digest"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Package": {
      "properties": {
        "name": {
          "type": "string"
        },
        "version": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "name",
        "version"
      ]
    }
  }
}
```
