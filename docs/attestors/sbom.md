# SBOM Attestor

The SBOM attestor records the contents of any [products](./product.md) that are valid [CycloneDX](https://cyclonedx.org/specification/overview/) or [SPDX](https://spdx.dev/learn/overview/) json files.  The SBOM file is parsed and the contents are recorded in the attestation.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/sbom/sbom-attestor",
  "$ref": "#/$defs/SBOMAttestor",
  "$defs": {
    "SBOMAttestor": {
      "properties": {
        "SBOMDocument": {
          "title": "SBOM Document",
          "description": "The Software Bill of Materials document (SPDX or CycloneDX format)"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "SBOMDocument"
      ]
    }
  }
}
```
