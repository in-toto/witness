# Environment Attestor

> Warning! Environment variables can contain SENSITIVE data that should not be
> shown. Review variables in your environment and use the `--env-add-sensitive-key`
> to exclude them from the capture if they are not covered by the default
> sensitive vars.

The Environment Attestor records the OS, hostname, username, and all environment variables set
at execution time. The default mode is running in obfuscation mode that will capture all variables
but it will obfuscate any variable that is in the sensitive vars list.

## Filter instead of obfuscate

When you use `--env-filter-sensitive-vars` it will remove sensitive vars completely
from the list.

## Adding additional sensitive keys

If you want to add keys to the sensitive list, either specific or with a glob,
you can use `--env-add-sensitive-key 'FOO'` for `FOO` or
 `--env-add-sensitive-key 'FOO*'` to also capture a variable like `FOO_BAR`.

## Explicitly allow sensitive key

There could be cases where you really want to have a specific key that is part
of the default sensitive vars list to be captured. You can do so by using the
`--env-allow-sensitive-key`.

## Default sensitive vars

The attestor has a default sensitive vars list. You can find the list in the
code base [here](https://github.com/in-toto/go-witness/blob/main/environment/sensitive_env_vars.go).

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "os": {
          "type": "string",
          "title": "Operating System",
          "description": "Operating system platform (e.g. linux"
        },
        "hostname": {
          "type": "string",
          "title": "Hostname",
          "description": "System hostname"
        },
        "username": {
          "type": "string",
          "title": "Username",
          "description": "Current user's username"
        },
        "variables": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object",
          "title": "Environment Variables",
          "description": "Captured environment variables based on policy"
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
