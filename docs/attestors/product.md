# Product Attestor

The Product Attestor examines materials recorded before a command was run and records all
products in the command. Digests and MIME types of any changed or created files are recorded as products.

## Subjects

All subjects are reported as subjects.
## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {},
      "additionalProperties": false,
      "type": "object"
    }
  }
}```
