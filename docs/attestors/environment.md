# Environment Attestor

The Environment Attestor records the OS, hostname, username, and all environment variables set
by TestifySec Witness at execution time.  Currently there is no means to block specific environment variables
so take care to not leak secrets stored in environment variables.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "os": {
          "type": "string"
        },
        "hostname": {
          "type": "string"
        },
        "username": {
          "type": "string"
        },
        "variables": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "os",
        "hostname",
        "username"
      ]
    }
  }
}
```
