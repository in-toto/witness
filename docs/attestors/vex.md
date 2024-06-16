## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "vexDocument": {
          "$ref": "#/$defs/VEX"
        },
        "reportFileName": {
          "type": "string"
        },
        "reportDigestSet": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "vexDocument"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Product": {
      "properties": {
        "@id": {
          "type": "string"
        },
        "hashes": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "identifiers": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "supplier": {
          "type": "string"
        },
        "subcomponents": {
          "items": {
            "$ref": "#/$defs/Subcomponent"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Statement": {
      "properties": {
        "@id": {
          "type": "string"
        },
        "vulnerability": {
          "$ref": "#/$defs/Vulnerability"
        },
        "timestamp": {
          "type": "string",
          "format": "date-time"
        },
        "last_updated": {
          "type": "string",
          "format": "date-time"
        },
        "products": {
          "items": {
            "$ref": "#/$defs/Product"
          },
          "type": "array"
        },
        "status": {
          "type": "string"
        },
        "status_notes": {
          "type": "string"
        },
        "justification": {
          "type": "string"
        },
        "impact_statement": {
          "type": "string"
        },
        "action_statement": {
          "type": "string"
        },
        "action_statement_timestamp": {
          "type": "string",
          "format": "date-time"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "status"
      ]
    },
    "Subcomponent": {
      "properties": {
        "@id": {
          "type": "string"
        },
        "hashes": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "identifiers": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "supplier": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "VEX": {
      "properties": {
        "@context": {
          "type": "string"
        },
        "@id": {
          "type": "string"
        },
        "author": {
          "type": "string"
        },
        "role": {
          "type": "string"
        },
        "timestamp": {
          "type": "string",
          "format": "date-time"
        },
        "last_updated": {
          "type": "string",
          "format": "date-time"
        },
        "version": {
          "type": "integer"
        },
        "tooling": {
          "type": "string"
        },
        "supplier": {
          "type": "string"
        },
        "statements": {
          "items": {
            "$ref": "#/$defs/Statement"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "@context",
        "@id",
        "author",
        "timestamp",
        "version",
        "statements"
      ]
    },
    "Vulnerability": {
      "properties": {
        "@id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "description": {
          "type": "string"
        },
        "aliases": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    }
  }
}
```
