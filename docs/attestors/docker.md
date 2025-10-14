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
          "type": "object",
          "title": "Docker Products",
          "description": "Map of Docker image digests to product information"
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
          "type": "object",
          "title": "Build Materials",
          "description": "Materials used to build the image by architecture"
        },
        "imagereferences": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "Image References",
          "description": "Docker image names and tags"
        },
        "imagedigest": {
          "$ref": "#/$defs/DigestSet",
          "title": "Image Digest",
          "description": "Content-addressable digest of the Docker image"
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
          "type": "string",
          "title": "Material URI",
          "description": "URI of the build material"
        },
        "architecture": {
          "type": "string",
          "title": "Architecture",
          "description": "Target architecture for this material"
        },
        "digest": {
          "$ref": "#/$defs/DigestSet",
          "title": "Material Digest",
          "description": "Cryptographic digest of the material"
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
