# Command Attestor

The Command Attestor collects information about a command that TestifySec Witness executes and observes.
The command arguments, exit code, stdout, and stderr will be collected and added to the attestation.

Witness can optionally trace the command which will record all subprocesses started by the parent process
as well as all files opened by all processes. Please note that tracing is currently supported only on
Linux operating systems and is considered experimental.

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/CommandRun",
  "$defs": {
    "CommandRun": {
      "properties": {
        "cmd": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "stdout": {
          "type": "string"
        },
        "stderr": {
          "type": "string"
        },
        "exitcode": {
          "type": "integer"
        },
        "processes": {
          "items": {
            "$ref": "#/$defs/ProcessInfo"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "cmd",
        "exitcode"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "ProcessInfo": {
      "properties": {
        "program": {
          "type": "string"
        },
        "processid": {
          "type": "integer"
        },
        "parentpid": {
          "type": "integer"
        },
        "programdigest": {
          "$ref": "#/$defs/DigestSet"
        },
        "comm": {
          "type": "string"
        },
        "cmdline": {
          "type": "string"
        },
        "exedigest": {
          "$ref": "#/$defs/DigestSet"
        },
        "openedfiles": {
          "additionalProperties": {
            "$ref": "#/$defs/DigestSet"
          },
          "type": "object"
        },
        "environ": {
          "type": "string"
        },
        "specbypassisvuln": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "processid",
        "parentpid"
      ]
    }
  }
}```
