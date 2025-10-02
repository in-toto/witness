# Docker Attestor

The Docker Attestor captures metadata about Docker container builds, including image digests, image references (tags), and build materials (base images and their layers). This attestor integrates with Docker's build metadata export feature to provide comprehensive supply chain tracking for container images.

## Use Cases

- Container supply chain tracking: Record provenance of all base images and layers used in builds
- Build reproducibility: Capture exact image digests to enable bit-for-bit reproducible container builds
- Vulnerability correlation: Link vulnerabilities in base images to downstream container builds
- Policy enforcement: Verify that only approved base images are used in production builds

## Usage

To use the Docker attestor, you need to run the Docker build command with the `--metadata-file` flag. This allows the attestor to capture build metadata and materials.

Example:
```bash
witness run --step build -a docker -o test-att.json -- docker build --metadata-file metadata.json -t example-tag .
```

## Configuration Options

| Option | Description |
|--------|-------------|
| `--metadata-file` | Docker build flag to export build metadata to a file (required for the attestor to capture build information) |

## Subjects

| Subject | Description |
| ------- | ----------- |
| Image digests | SHA256 digests of the built container image for verification |
| Image references | Tags applied to the built image (e.g., `example-tag:latest`) |
| Build materials | Base image digests and URIs used as inputs to the build process |

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
