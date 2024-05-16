# Link Attestor

The Link Attestor generates an [in-toto Link attestation](https://in-toto.readthedocs.io/en/latest/in-toto-spec.html#link) for the step that it is invoked on.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/attestation/go/predicates/link/v0/link",
  "$ref": "#/$defs/Link",
  "$defs": {
    "Link": {
      "properties": {
        "name": {
          "type": "string"
        },
        "command": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "materials": {
          "items": {
            "$ref": "#/$defs/ResourceDescriptor"
          },
          "type": "array"
        },
        "byproducts": {
          "$ref": "#/$defs/Struct"
        },
        "environment": {
          "$ref": "#/$defs/Struct"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "ResourceDescriptor": {
      "properties": {
        "name": {
          "type": "string"
        },
        "uri": {
          "type": "string"
        },
        "digest": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "content": {
          "type": "string",
          "contentEncoding": "base64"
        },
        "download_location": {
          "type": "string"
        },
        "media_type": {
          "type": "string"
        },
        "annotations": {
          "$ref": "#/$defs/Struct"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Struct": {
      "properties": {
        "fields": {
          "additionalProperties": {
            "$ref": "#/$defs/Value"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Value": {
      "properties": {
        "Kind": true
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Kind"
      ]
    }
  }
}
```
