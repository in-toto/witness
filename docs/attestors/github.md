# Github Attestor

The [Github](https://github.com/about) Attestor records information about the [GitHub Actions](https://docs.github.com/en/actions) workflow execution in which Witness was run. Witness verifies the JWT ([JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)) provided by the token service (configured with the `ACTIONS_ID_TOKEN_REQUEST_URL` environment variable) against the Github's JWKS ([JSON Web Key Set](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)) to ensure authenticity at execution time.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `pipelineurl` | URL of the CI/CD pipeline to which this job belonged  |
| `projecturl` | URL of the project that owns the CI/CD pipeline and job |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "jwt": {
          "$schema": "https://json-schema.org/draft/2020-12/schema",
          "$ref": "#/$defs/Attestor",
          "$defs": {
            "Attestor": {
              "properties": {
                "claims": {
                  "type": "object",
                  "title": "Claims",
                  "description": "JWT claims extracted from the token"
                },
                "verifiedBy": {
                  "$ref": "#/$defs/VerificationInfo",
                  "title": "Verified By",
                  "description": "Information about how the JWT was verified"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "claims"
              ]
            },
            "AttributeTypeAndValue": {
              "properties": {
                "Type": {
                  "$ref": "#/$defs/ObjectIdentifier"
                },
                "Value": true
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "Type",
                "Value"
              ]
            },
            "Certificate": {
              "properties": {
                "Raw": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "RawTBSCertificate": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "RawSubjectPublicKeyInfo": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "RawSubject": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "RawIssuer": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "Signature": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "SignatureAlgorithm": {
                  "type": "integer"
                },
                "PublicKeyAlgorithm": {
                  "type": "integer"
                },
                "PublicKey": true,
                "Version": {
                  "type": "integer"
                },
                "SerialNumber": {
                  "$ref": "#/$defs/Int"
                },
                "Issuer": {
                  "$ref": "#/$defs/Name"
                },
                "Subject": {
                  "$ref": "#/$defs/Name"
                },
                "NotBefore": {
                  "type": "string",
                  "format": "date-time"
                },
                "NotAfter": {
                  "type": "string",
                  "format": "date-time"
                },
                "KeyUsage": {
                  "type": "integer"
                },
                "Extensions": {
                  "items": {
                    "$ref": "#/$defs/Extension"
                  },
                  "type": "array"
                },
                "ExtraExtensions": {
                  "items": {
                    "$ref": "#/$defs/Extension"
                  },
                  "type": "array"
                },
                "UnhandledCriticalExtensions": {
                  "items": {
                    "$ref": "#/$defs/ObjectIdentifier"
                  },
                  "type": "array"
                },
                "ExtKeyUsage": {
                  "items": {
                    "type": "integer"
                  },
                  "type": "array"
                },
                "UnknownExtKeyUsage": {
                  "items": {
                    "$ref": "#/$defs/ObjectIdentifier"
                  },
                  "type": "array"
                },
                "BasicConstraintsValid": {
                  "type": "boolean"
                },
                "IsCA": {
                  "type": "boolean"
                },
                "MaxPathLen": {
                  "type": "integer"
                },
                "MaxPathLenZero": {
                  "type": "boolean"
                },
                "SubjectKeyId": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "AuthorityKeyId": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "OCSPServer": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "IssuingCertificateURL": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "DNSNames": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "EmailAddresses": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "IPAddresses": {
                  "items": {
                    "type": "string",
                    "format": "ipv4"
                  },
                  "type": "array"
                },
                "URIs": {
                  "items": {
                    "type": "string",
                    "format": "uri"
                  },
                  "type": "array"
                },
                "PermittedDNSDomainsCritical": {
                  "type": "boolean"
                },
                "PermittedDNSDomains": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "ExcludedDNSDomains": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "PermittedIPRanges": {
                  "items": {
                    "$ref": "#/$defs/IPNet"
                  },
                  "type": "array"
                },
                "ExcludedIPRanges": {
                  "items": {
                    "$ref": "#/$defs/IPNet"
                  },
                  "type": "array"
                },
                "PermittedEmailAddresses": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "ExcludedEmailAddresses": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "PermittedURIDomains": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "ExcludedURIDomains": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "CRLDistributionPoints": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "PolicyIdentifiers": {
                  "items": {
                    "$ref": "#/$defs/ObjectIdentifier"
                  },
                  "type": "array"
                },
                "Policies": {
                  "items": {
                    "$ref": "#/$defs/OID"
                  },
                  "type": "array"
                },
                "InhibitAnyPolicy": {
                  "type": "integer"
                },
                "InhibitAnyPolicyZero": {
                  "type": "boolean"
                },
                "InhibitPolicyMapping": {
                  "type": "integer"
                },
                "InhibitPolicyMappingZero": {
                  "type": "boolean"
                },
                "RequireExplicitPolicy": {
                  "type": "integer"
                },
                "RequireExplicitPolicyZero": {
                  "type": "boolean"
                },
                "PolicyMappings": {
                  "items": {
                    "$ref": "#/$defs/PolicyMapping"
                  },
                  "type": "array"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "Raw",
                "RawTBSCertificate",
                "RawSubjectPublicKeyInfo",
                "RawSubject",
                "RawIssuer",
                "Signature",
                "SignatureAlgorithm",
                "PublicKeyAlgorithm",
                "PublicKey",
                "Version",
                "SerialNumber",
                "Issuer",
                "Subject",
                "NotBefore",
                "NotAfter",
                "KeyUsage",
                "Extensions",
                "ExtraExtensions",
                "UnhandledCriticalExtensions",
                "ExtKeyUsage",
                "UnknownExtKeyUsage",
                "BasicConstraintsValid",
                "IsCA",
                "MaxPathLen",
                "MaxPathLenZero",
                "SubjectKeyId",
                "AuthorityKeyId",
                "OCSPServer",
                "IssuingCertificateURL",
                "DNSNames",
                "EmailAddresses",
                "IPAddresses",
                "URIs",
                "PermittedDNSDomainsCritical",
                "PermittedDNSDomains",
                "ExcludedDNSDomains",
                "PermittedIPRanges",
                "ExcludedIPRanges",
                "PermittedEmailAddresses",
                "ExcludedEmailAddresses",
                "PermittedURIDomains",
                "ExcludedURIDomains",
                "CRLDistributionPoints",
                "PolicyIdentifiers",
                "Policies",
                "InhibitAnyPolicy",
                "InhibitAnyPolicyZero",
                "InhibitPolicyMapping",
                "InhibitPolicyMappingZero",
                "RequireExplicitPolicy",
                "RequireExplicitPolicyZero",
                "PolicyMappings"
              ]
            },
            "Extension": {
              "properties": {
                "Id": {
                  "$ref": "#/$defs/ObjectIdentifier"
                },
                "Critical": {
                  "type": "boolean"
                },
                "Value": {
                  "type": "string",
                  "contentEncoding": "base64"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "Id",
                "Critical",
                "Value"
              ]
            },
            "IPMask": {
              "type": "string",
              "contentEncoding": "base64"
            },
            "IPNet": {
              "properties": {
                "IP": {
                  "type": "string",
                  "format": "ipv4"
                },
                "Mask": {
                  "$ref": "#/$defs/IPMask"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "IP",
                "Mask"
              ]
            },
            "Int": {
              "properties": {},
              "additionalProperties": false,
              "type": "object"
            },
            "JSONWebKey": {
              "properties": {
                "Key": true,
                "KeyID": {
                  "type": "string"
                },
                "Algorithm": {
                  "type": "string"
                },
                "Use": {
                  "type": "string"
                },
                "Certificates": {
                  "items": {
                    "$ref": "#/$defs/Certificate"
                  },
                  "type": "array"
                },
                "CertificatesURL": {
                  "type": "string",
                  "format": "uri"
                },
                "CertificateThumbprintSHA1": {
                  "type": "string",
                  "contentEncoding": "base64"
                },
                "CertificateThumbprintSHA256": {
                  "type": "string",
                  "contentEncoding": "base64"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "Key",
                "KeyID",
                "Algorithm",
                "Use",
                "Certificates",
                "CertificatesURL",
                "CertificateThumbprintSHA1",
                "CertificateThumbprintSHA256"
              ]
            },
            "Name": {
              "properties": {
                "Country": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "Organization": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "OrganizationalUnit": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "Locality": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "Province": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "StreetAddress": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "PostalCode": {
                  "items": {
                    "type": "string"
                  },
                  "type": "array"
                },
                "SerialNumber": {
                  "type": "string"
                },
                "CommonName": {
                  "type": "string"
                },
                "Names": {
                  "items": {
                    "$ref": "#/$defs/AttributeTypeAndValue"
                  },
                  "type": "array"
                },
                "ExtraNames": {
                  "items": {
                    "$ref": "#/$defs/AttributeTypeAndValue"
                  },
                  "type": "array"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "Country",
                "Organization",
                "OrganizationalUnit",
                "Locality",
                "Province",
                "StreetAddress",
                "PostalCode",
                "SerialNumber",
                "CommonName",
                "Names",
                "ExtraNames"
              ]
            },
            "OID": {
              "properties": {},
              "additionalProperties": false,
              "type": "object"
            },
            "ObjectIdentifier": {
              "items": {
                "type": "integer"
              },
              "type": "array"
            },
            "PolicyMapping": {
              "properties": {
                "IssuerDomainPolicy": {
                  "$ref": "#/$defs/OID"
                },
                "SubjectDomainPolicy": {
                  "$ref": "#/$defs/OID"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "IssuerDomainPolicy",
                "SubjectDomainPolicy"
              ]
            },
            "VerificationInfo": {
              "properties": {
                "jwksUrl": {
                  "type": "string",
                  "title": "JWKS URL",
                  "description": "URL where the JSON Web Key Set can be found"
                },
                "jwk": {
                  "$ref": "#/$defs/JSONWebKey",
                  "title": "JWK",
                  "description": "The JSON Web Key used to verify the token"
                }
              },
              "additionalProperties": false,
              "type": "object",
              "required": [
                "jwksUrl",
                "jwk"
              ]
            }
          }
        },
        "ciconfigpath": {
          "type": "string",
          "title": "CI Config Path",
          "description": "Path to the GitHub Actions workflow file"
        },
        "pipelineid": {
          "type": "string",
          "title": "Pipeline ID",
          "description": "GitHub Actions run ID",
          "examples": [
            "1234567890"
          ]
        },
        "pipelinename": {
          "type": "string",
          "title": "Pipeline Name",
          "description": "Name of the GitHub workflow"
        },
        "pipelineurl": {
          "type": "string",
          "title": "Pipeline URL",
          "description": "URL to the GitHub Actions run"
        },
        "projecturl": {
          "type": "string",
          "title": "Project URL",
          "description": "URL to the GitHub repository"
        },
        "runnerid": {
          "type": "string",
          "title": "Runner ID",
          "description": "Name of the GitHub Actions runner"
        },
        "cihost": {
          "type": "string",
          "title": "CI Host",
          "description": "GitHub server hostname"
        },
        "ciserverurl": {
          "type": "string",
          "title": "CI Server URL",
          "description": "GitHub server URL",
          "examples": [
            "https://github.com"
          ]
        },
        "runnerarch": {
          "type": "string",
          "title": "Runner Architecture",
          "description": "Architecture of the runner",
          "examples": [
            "X64"
          ]
        },
        "runneros": {
          "type": "string",
          "title": "Runner OS",
          "description": "Operating system of the runner",
          "examples": [
            "Linux"
          ]
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "ciconfigpath",
        "pipelineid",
        "pipelinename",
        "pipelineurl",
        "projecturl",
        "runnerid",
        "cihost",
        "ciserverurl",
        "runnerarch",
        "runneros"
      ]
    }
  }
}
```
