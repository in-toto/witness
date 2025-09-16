# Product Attestor

The Product Attestor examines materials recorded before a command was run and records all
products in the command. Digests and MIME types of any changed or created files are recorded as products.

## Subjects

All subjects are reported as subjects.
## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$defs": {
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Product": {
      "properties": {
        "mime_type": {
          "type": "string"
        },
        "digest": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "mime_type",
        "digest"
      ]
    }
  },
  "properties": {
    "Products": {
      "additionalProperties": {
        "$ref": "#/$defs/Product"
      },
      "type": "object"
    }
  },
  "additionalProperties": false,
  "type": "object",
  "required": [
    "Products"
  ]
}
```
