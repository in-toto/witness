# System Packages Attestor

The System Packages Attestor captures an inventory of all system packages installed in the build environment at the time of attestation. It auto-detects the package manager (dpkg for Debian/Ubuntu, rpm for RedHat/Fedora/CentOS) based on the OS configuration and records package names, versions, and a digest of the complete package list.

## Use Cases

- Supply chain security: Track exact system package versions used during build
- Reproducible builds: Ensure build environments can be recreated with identical package versions
- Vulnerability tracking: Identify which builds may be affected by package vulnerabilities
- Compliance and auditing: Provide evidence of build environment configuration

## Usage

```bash
witness run --step build -a system-packages -o attestation.json -- make build
```

The attestor automatically detects the package manager from `/etc/os-release` and collects the package inventory without additional configuration.

## Configuration

The System Packages Attestor requires no configuration flags. It automatically:
- Detects the operating system from `/etc/os-release`
- Selects the appropriate package manager (dpkg or rpm)
- Queries all installed packages with their versions
- Generates a cryptographic digest of the complete package list

## Subjects

| Subject | Description |
| ------- | ----------- |
| Package inventory digest | SHA256 hash of the complete system package list, enabling verification of the exact build environment |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/system-packages/attestor",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "os": {
          "type": "string"
        },
        "distribution": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "packages": {
          "items": {
            "$ref": "#/$defs/Package"
          },
          "type": "array"
        },
        "digest": {
          "$ref": "#/$defs/DigestSet"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "os",
        "distribution",
        "version",
        "packages",
        "digest"
      ]
    },
    "DigestSet": {
      "additionalProperties": {
        "type": "string"
      },
      "type": "object"
    },
    "Package": {
      "properties": {
        "name": {
          "type": "string"
        },
        "version": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "name",
        "version"
      ]
    }
  }
}
```
