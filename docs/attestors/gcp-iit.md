# GCP Instance Identity Attestor

The [Google Cloud Platform](https://console.cloud.google.com/getting-started?supportedpurview=project) (GCP) Instance Identity Attestor communicates with the [GCP metadata server](https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata) to collect information
about the instance on which TestifySec Witness is being exected. The instance identity JSON Web Token signature is validated
against Google's JWKS ([JSON Web Key Set](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)) to ensure authenticity.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `instanceid` | ID of the Google Compute instance on which Witness was executed |
| `instancename` | Name of the Compute instance on which Witness was executed |
| `projectid` | The ID of the project to which the instance belonged |
| `projectnumber` | Number of the project to which the instance belonged |
| `clusteruid` | UID of the cluster if the execution environment was a [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine) (GKE) cluster |

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
                  "type": "object"
                },
                "verifiedBy": {
                  "$ref": "#/$defs/VerificationInfo"
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
                "Policies"
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
            "VerificationInfo": {
              "properties": {
                "jwksUrl": {
                  "type": "string"
                },
                "jwk": {
                  "$ref": "#/$defs/JSONWebKey"
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
        "project_id": {
          "type": "string"
        },
        "project_number": {
          "type": "string"
        },
        "zone": {
          "type": "string"
        },
        "instance_id": {
          "type": "string"
        },
        "instance_hostname": {
          "type": "string"
        },
        "instance_creation_timestamp": {
          "type": "string"
        },
        "instance_confidentiality": {
          "type": "string"
        },
        "licence_id": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "cluster_name": {
          "type": "string"
        },
        "cluster_uid": {
          "type": "string"
        },
        "cluster_location": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "jwt",
        "project_id",
        "project_number",
        "zone",
        "instance_id",
        "instance_hostname",
        "instance_creation_timestamp",
        "instance_confidentiality",
        "licence_id",
        "cluster_name",
        "cluster_uid",
        "cluster_location"
      ]
    }
  }
}
```
