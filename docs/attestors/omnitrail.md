## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "Envelope": {
          "$ref": "#/$defs/Envelope",
          "title": "Envelope",
          "description": "Omnitrail envelope containing artifact trail information"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Envelope"
      ]
    },
    "Element": {
      "properties": {
        "type": {
          "type": "string"
        },
        "sha1": {
          "type": "string"
        },
        "sha256": {
          "type": "string"
        },
        "gitoid:sha1": {
          "type": "string"
        },
        "gitoid:sha256": {
          "type": "string"
        },
        "posix": {
          "$ref": "#/$defs/Posix"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "type"
      ]
    },
    "Envelope": {
      "properties": {
        "header": {
          "$ref": "#/$defs/Header"
        },
        "mapping": {
          "additionalProperties": {
            "$ref": "#/$defs/Element"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "header",
        "mapping"
      ]
    },
    "Feature": {
      "properties": {
        "algorithms": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "Header": {
      "properties": {
        "features": {
          "additionalProperties": {
            "$ref": "#/$defs/Feature"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "features"
      ]
    },
    "Posix": {
      "properties": {
        "atime": {
          "type": "string"
        },
        "ctime": {
          "type": "string"
        },
        "creation_time": {
          "type": "string"
        },
        "extended_attributes": {
          "type": "string"
        },
        "file_device_id": {
          "type": "string"
        },
        "file_flags": {
          "type": "string"
        },
        "file_inode": {
          "type": "string"
        },
        "file_system_id": {
          "type": "string"
        },
        "file_type": {
          "type": "string"
        },
        "hard_link_count": {
          "type": "string"
        },
        "mtime": {
          "type": "string"
        },
        "metadata_ctime": {
          "type": "string"
        },
        "owner_gid": {
          "type": "string"
        },
        "owner_uid": {
          "type": "string"
        },
        "permissions": {
          "type": "string"
        },
        "size": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    }
  }
}
```
