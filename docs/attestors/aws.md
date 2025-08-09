# AWS Instance Identity Attestor

The AWS (Amazon Web Services) Instance Identity Attestor communicates with the AWS Instance Metadata to collect
information about the AWS instance Witness on which executing. The document signature is
verified with the AWS RSA public certificate available [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html).
This verification method currently does not work for the Hong Kong, Bahrain, Cape Town, Milan, China, or
GovCloud regions.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `instanceid` | The ID of the AWS instance where Witness was executed |
| `accountid` | ID of the account that owns the AWS instance |
| `imageid` | ID of the AMI ([Amazon Machine Image](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)) the instance was running at time of execution |
| `privateip` | IP address of the instance at time of execution |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "devpayProductCodes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "marketplaceProductCodes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "availabilityZone": {
          "type": "string"
        },
        "privateIp": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "region": {
          "type": "string"
        },
        "instanceId": {
          "type": "string"
        },
        "billingProducts": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "instanceType": {
          "type": "string"
        },
        "accountId": {
          "type": "string"
        },
        "pendingTime": {
          "type": "string",
          "format": "date-time"
        },
        "imageId": {
          "type": "string"
        },
        "kernelId": {
          "type": "string"
        },
        "ramdiskId": {
          "type": "string"
        },
        "architecture": {
          "type": "string"
        },
        "rawiid": {
          "type": "string",
          "title": "Raw Instance Identity Document",
          "description": "Base64 encoded raw instance identity document from AWS"
        },
        "rawsig": {
          "type": "string",
          "title": "Raw Signature",
          "description": "Base64 encoded signature of the instance identity document"
        },
        "publickey": {
          "type": "string",
          "title": "Public Key",
          "description": "Public key used to verify the instance identity document signature"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "devpayProductCodes",
        "marketplaceProductCodes",
        "availabilityZone",
        "privateIp",
        "version",
        "region",
        "instanceId",
        "billingProducts",
        "instanceType",
        "accountId",
        "pendingTime",
        "imageId",
        "kernelId",
        "ramdiskId",
        "architecture",
        "rawiid",
        "rawsig",
        "publickey"
      ]
    }
  }
}
```
