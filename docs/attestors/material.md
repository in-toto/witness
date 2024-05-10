# Material Attestor

The Material Attestor records the digests of all files in the working directory of TestifySec Witness
at exection time, but before any command is run.  This recording provides information about the state
of all files before any changes are made by a command.

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
    }
  },
  "properties": {
    "Materials": {
      "additionalProperties": {
        "$ref": "#/$defs/DigestSet"
      },
      "type": "object"
    }
  },
  "additionalProperties": false,
  "type": "object",
  "required": [
    "Materials"
  ]
}```
