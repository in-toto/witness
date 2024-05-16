# Collection

Witness enables users to generate a wide variety of attestation predicates (arbitrary metadata about a subject artifact, with a type-specific schema) through the use of attestors. For each `witness run`, multiple attestors can be specified and therefore multiple predicates can be
generated as an output. Witness correlates each `run` invocation to a "step" in an artifacts supply-chain lifecycle (the name of which is determine by the `--step` flag). Witness therefore needs a way of bundling these predicates together to form a complete representation of that specific step, but also to avoid the repeated process of signing multiple statements. The `Collection` object is a predicate type that achieves this.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/collection",
  "$ref": "#/$defs/Collection",
  "$defs": {
    "Collection": {
      "properties": {
        "name": {
          "type": "string"
        },
        "attestations": {
          "items": {
            "$ref": "#/$defs/CollectionAttestation"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "name",
        "attestations"
      ]
    },
    "CollectionAttestation": {
      "properties": {
        "type": {
          "type": "string"
        },
        "attestation": true,
        "starttime": {
          "type": "string",
          "format": "date-time"
        },
        "endtime": {
          "type": "string",
          "format": "date-time"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "type",
        "attestation",
        "starttime",
        "endtime"
      ]
    }
  }
}
```
