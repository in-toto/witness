# Docker Attestor

## Usage

To use the Docker attestor, you need to run the Docker build command with the `--metadata-file` flag. This allows the attestor to capture build metadata and materials.

Example:
```bash
witness run --step build -a docker -o test-att.json -- docker build --metadata-file metadata.json -t example-tag .
```

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "products": {
          "additionalProperties": {
            "$ref": "#/$defs/DockerProduct"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "products"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "DockerProduct": {
      "properties": {
        "materials": {
          "additionalProperties": {
            "items": {
              "$ref": "#/$defs/Material"
            },
            "type": "array"
          },
          "type": "object"
        },
        "imagereferences": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "imagedigest": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "materials",
        "imagereferences",
        "imagedigest"
      ]
    },
    "Material": {
      "properties": {
        "uri": {
          "type": "string"
        },
        "architecture": {
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
        "architecture",
        "digest"
      ]
    }
  }
}
```
