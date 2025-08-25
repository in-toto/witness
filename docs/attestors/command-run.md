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
          "type": "array",
          "title": "Command",
          "description": "Command and arguments to execute"
        },
        "stdout": {
          "type": "string",
          "title": "Standard Output",
          "description": "Captured stdout from the command"
        },
        "stderr": {
          "type": "string",
          "title": "Standard Error",
          "description": "Captured stderr from the command"
        },
        "exitcode": {
          "type": "integer",
          "title": "Exit Code",
          "description": "Command exit code"
        },
        "processes": {
          "items": {
            "$ref": "#/$defs/ProcessInfo"
          },
          "type": "array",
          "title": "Process Information",
          "description": "Detailed process execution information when tracing is enabled"
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
          "type": "string",
          "title": "Program Path",
          "description": "Path to the executed program"
        },
        "processid": {
          "type": "integer",
          "title": "Process ID",
          "description": "Process identifier"
        },
        "parentpid": {
          "type": "integer",
          "title": "Parent Process ID",
          "description": "Parent process identifier"
        },
        "programdigest": {
          "$ref": "#/$defs/DigestSet",
          "title": "Program Digest",
          "description": "Cryptographic digest of the program binary"
        },
        "comm": {
          "type": "string",
          "title": "Command Name",
          "description": "Command name from /proc/[pid]/comm"
        },
        "cmdline": {
          "type": "string",
          "title": "Command Line",
          "description": "Full command line from /proc/[pid]/cmdline"
        },
        "exedigest": {
          "$ref": "#/$defs/DigestSet",
          "title": "Executable Digest",
          "description": "Cryptographic digest of the executable"
        },
        "openedfiles": {
          "additionalProperties": {
            "$ref": "#/$defs/DigestSet"
          },
          "type": "object",
          "title": "Opened Files",
          "description": "Files opened during execution with their digests"
        },
        "environ": {
          "type": "string",
          "title": "Environment",
          "description": "Process environment variables"
        },
        "specbypassisvuln": {
          "type": "boolean",
          "title": "Speculative Bypass Vulnerability",
          "description": "Whether CPU is vulnerable to speculative execution attacks"
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
}
```
