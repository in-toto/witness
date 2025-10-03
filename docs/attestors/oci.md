# OCI Attestor

The OCI Attestor records information about a provided [Open Container Initiative](https://opencontainers.org/) (OCI) image stored on disk as a tarball.
Information about the image tags, layers, and manifest are collected and reported in this
attestation.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `tardigest` | Digest of the tarred image |
| `imageid` | ID of the image |
| `layerdiffid` | Layer diff IDs of the image |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "tardigest": {
          "$ref": "#/$defs/DigestSet",
          "title": "TAR Digest",
          "description": "Digest of the OCI image TAR file"
        },
        "manifest": {
          "items": {
            "$ref": "#/$defs/Manifest"
          },
          "type": "array",
          "title": "Manifest",
          "description": "OCI image manifest information"
        },
        "imagetags": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "Image Tags",
          "description": "Tags associated with the OCI image"
        },
        "diffids": {
          "items": {
            "$ref": "#/$defs/DigestSet"
          },
          "type": "array",
          "title": "Layer Diff IDs",
          "description": "Diff IDs for each layer in the image"
        },
        "imageid": {
          "$ref": "#/$defs/DigestSet",
          "title": "Image ID",
          "description": "Digest of the image configuration"
        },
        "manifestraw": {
          "type": "string",
          "contentEncoding": "base64",
          "title": "Raw Manifest",
          "description": "Raw manifest.json content"
        },
        "manifestdigest": {
          "$ref": "#/$defs/DigestSet",
          "title": "Manifest Digest",
          "description": "Digest of the manifest.json file"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "tardigest",
        "manifest",
        "imagetags",
        "diffids",
        "imageid",
        "manifestraw",
        "manifestdigest"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Manifest": {
      "properties": {
        "Config": {
          "type": "string",
          "title": "Config",
          "description": "Path to the image configuration file"
        },
        "RepoTags": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "Repository Tags",
          "description": "Repository tags for the image"
        },
        "Layers": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "Layers",
          "description": "Paths to layer TAR files"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Config",
        "RepoTags",
        "Layers"
      ]
    }
  }
}
```
