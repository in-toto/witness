# SLSA Attestor

The SLSA Attestor generates a [SLSA Provenance](https://slsa.dev/spec/v1.0/provenance) attestation for the step that it is invoked on.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/attestation/go/predicates/provenance/v1/provenance",
  "$ref": "#/$defs/Provenance",
  "$defs": {
    "BuildDefinition": {
      "properties": {
        "build_type": {
          "type": "string"
        },
        "external_parameters": {
          "$ref": "#/$defs/Struct"
        },
        "internal_parameters": {
          "$ref": "#/$defs/Struct"
        },
        "resolved_dependencies": {
          "items": {
            "$ref": "#/$defs/ResourceDescriptor"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "BuildMetadata": {
      "properties": {
        "invocation_id": {
          "type": "string"
        },
        "started_on": {
          "$ref": "#/$defs/Timestamp"
        },
        "finished_on": {
          "$ref": "#/$defs/Timestamp"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Builder": {
      "properties": {
        "id": {
          "type": "string"
        },
        "version": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "builder_dependencies": {
          "items": {
            "$ref": "#/$defs/ResourceDescriptor"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Provenance": {
      "properties": {
        "build_definition": {
          "$ref": "#/$defs/BuildDefinition"
        },
        "run_details": {
          "$ref": "#/$defs/RunDetails"
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
    "RunDetails": {
      "properties": {
        "builder": {
          "$ref": "#/$defs/Builder"
        },
        "metadata": {
          "$ref": "#/$defs/BuildMetadata"
        },
        "byproducts": {
          "items": {
            "$ref": "#/$defs/ResourceDescriptor"
          },
          "type": "array"
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
    "Timestamp": {
      "properties": {
        "seconds": {
          "type": "integer"
        },
        "nanos": {
          "type": "integer"
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
}```
