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
          "$ref": "#/$defs/DigestSet"
        },
        "manifest": {
          "items": {
            "$ref": "#/$defs/Manifest"
          },
          "type": "array"
        },
        "imagetags": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "diffids": {
          "items": {
            "$ref": "#/$defs/DigestSet"
          },
          "type": "array"
        },
        "imageid": {
          "$ref": "#/$defs/DigestSet"
        },
        "manifestraw": {
          "type": "string",
          "contentEncoding": "base64"
        },
        "manifestdigest": {
          "$ref": "#/$defs/DigestSet"
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
          "type": "string"
        },
        "RepoTags": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "Layers": {
          "items": {
            "type": "string"
          },
          "type": "array"
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
