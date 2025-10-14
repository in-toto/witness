## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/aws-codebuild/attestor",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "build_info": {
          "$ref": "#/$defs/BuildInfo"
        },
        "raw_build_details": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "build_info"
      ]
    },
    "AutoRetryConfig": {
      "properties": {
        "AutoRetryLimit": {
          "type": "integer"
        },
        "AutoRetryNumber": {
          "type": "integer"
        },
        "NextAutoRetry": {
          "type": "string"
        },
        "PreviousAutoRetry": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "AutoRetryLimit",
        "AutoRetryNumber",
        "NextAutoRetry",
        "PreviousAutoRetry"
      ]
    },
    "Build": {
      "properties": {
        "Arn": {
          "type": "string"
        },
        "Artifacts": {
          "$ref": "#/$defs/BuildArtifacts"
        },
        "AutoRetryConfig": {
          "$ref": "#/$defs/AutoRetryConfig"
        },
        "BuildBatchArn": {
          "type": "string"
        },
        "BuildComplete": {
          "type": "boolean"
        },
        "BuildNumber": {
          "type": "integer"
        },
        "BuildStatus": {
          "type": "string"
        },
        "Cache": {
          "$ref": "#/$defs/ProjectCache"
        },
        "CurrentPhase": {
          "type": "string"
        },
        "DebugSession": {
          "$ref": "#/$defs/DebugSession"
        },
        "EncryptionKey": {
          "type": "string"
        },
        "EndTime": {
          "type": "string",
          "format": "date-time"
        },
        "Environment": {
          "$ref": "#/$defs/ProjectEnvironment"
        },
        "ExportedEnvironmentVariables": {
          "items": {
            "$ref": "#/$defs/ExportedEnvironmentVariable"
          },
          "type": "array"
        },
        "FileSystemLocations": {
          "items": {
            "$ref": "#/$defs/ProjectFileSystemLocation"
          },
          "type": "array"
        },
        "Id": {
          "type": "string"
        },
        "Initiator": {
          "type": "string"
        },
        "Logs": {
          "$ref": "#/$defs/LogsLocation"
        },
        "NetworkInterface": {
          "$ref": "#/$defs/NetworkInterface"
        },
        "Phases": {
          "items": {
            "$ref": "#/$defs/BuildPhase"
          },
          "type": "array"
        },
        "ProjectName": {
          "type": "string"
        },
        "QueuedTimeoutInMinutes": {
          "type": "integer"
        },
        "ReportArns": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "ResolvedSourceVersion": {
          "type": "string"
        },
        "SecondaryArtifacts": {
          "items": {
            "$ref": "#/$defs/BuildArtifacts"
          },
          "type": "array"
        },
        "SecondarySourceVersions": {
          "items": {
            "$ref": "#/$defs/ProjectSourceVersion"
          },
          "type": "array"
        },
        "SecondarySources": {
          "items": {
            "$ref": "#/$defs/ProjectSource"
          },
          "type": "array"
        },
        "ServiceRole": {
          "type": "string"
        },
        "Source": {
          "$ref": "#/$defs/ProjectSource"
        },
        "SourceVersion": {
          "type": "string"
        },
        "StartTime": {
          "type": "string",
          "format": "date-time"
        },
        "TimeoutInMinutes": {
          "type": "integer"
        },
        "VpcConfig": {
          "$ref": "#/$defs/VpcConfig"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Arn",
        "Artifacts",
        "AutoRetryConfig",
        "BuildBatchArn",
        "BuildComplete",
        "BuildNumber",
        "BuildStatus",
        "Cache",
        "CurrentPhase",
        "DebugSession",
        "EncryptionKey",
        "EndTime",
        "Environment",
        "ExportedEnvironmentVariables",
        "FileSystemLocations",
        "Id",
        "Initiator",
        "Logs",
        "NetworkInterface",
        "Phases",
        "ProjectName",
        "QueuedTimeoutInMinutes",
        "ReportArns",
        "ResolvedSourceVersion",
        "SecondaryArtifacts",
        "SecondarySourceVersions",
        "SecondarySources",
        "ServiceRole",
        "Source",
        "SourceVersion",
        "StartTime",
        "TimeoutInMinutes",
        "VpcConfig"
      ]
    },
    "BuildArtifacts": {
      "properties": {
        "ArtifactIdentifier": {
          "type": "string"
        },
        "BucketOwnerAccess": {
          "type": "string"
        },
        "EncryptionDisabled": {
          "type": "boolean"
        },
        "Location": {
          "type": "string"
        },
        "Md5sum": {
          "type": "string"
        },
        "OverrideArtifactName": {
          "type": "boolean"
        },
        "Sha256sum": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "ArtifactIdentifier",
        "BucketOwnerAccess",
        "EncryptionDisabled",
        "Location",
        "Md5sum",
        "OverrideArtifactName",
        "Sha256sum"
      ]
    },
    "BuildInfo": {
      "properties": {
        "build_id": {
          "type": "string"
        },
        "build_arn": {
          "type": "string"
        },
        "build_number": {
          "type": "string"
        },
        "project_name": {
          "type": "string"
        },
        "initiator": {
          "type": "string"
        },
        "source_version": {
          "type": "string"
        },
        "source_repo": {
          "type": "string"
        },
        "batch_build_id": {
          "type": "string"
        },
        "webhook_event": {
          "type": "string"
        },
        "webhook_head_ref": {
          "type": "string"
        },
        "webhook_actor_id": {
          "type": "string"
        },
        "region": {
          "type": "string"
        },
        "build_details": {
          "$ref": "#/$defs/Build"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "build_id"
      ]
    },
    "BuildPhase": {
      "properties": {
        "Contexts": {
          "items": {
            "$ref": "#/$defs/PhaseContext"
          },
          "type": "array"
        },
        "DurationInSeconds": {
          "type": "integer"
        },
        "EndTime": {
          "type": "string",
          "format": "date-time"
        },
        "PhaseStatus": {
          "type": "string"
        },
        "PhaseType": {
          "type": "string"
        },
        "StartTime": {
          "type": "string",
          "format": "date-time"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Contexts",
        "DurationInSeconds",
        "EndTime",
        "PhaseStatus",
        "PhaseType",
        "StartTime"
      ]
    },
    "BuildStatusConfig": {
      "properties": {
        "Context": {
          "type": "string"
        },
        "TargetUrl": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Context",
        "TargetUrl"
      ]
    },
    "CloudWatchLogsConfig": {
      "properties": {
        "Status": {
          "type": "string"
        },
        "GroupName": {
          "type": "string"
        },
        "StreamName": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Status",
        "GroupName",
        "StreamName"
      ]
    },
    "ComputeConfiguration": {
      "properties": {
        "Disk": {
          "type": "integer"
        },
        "InstanceType": {
          "type": "string"
        },
        "MachineType": {
          "type": "string"
        },
        "Memory": {
          "type": "integer"
        },
        "VCpu": {
          "type": "integer"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Disk",
        "InstanceType",
        "MachineType",
        "Memory",
        "VCpu"
      ]
    },
    "DebugSession": {
      "properties": {
        "SessionEnabled": {
          "type": "boolean"
        },
        "SessionTarget": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "SessionEnabled",
        "SessionTarget"
      ]
    },
    "DockerServer": {
      "properties": {
        "ComputeType": {
          "type": "string"
        },
        "SecurityGroupIds": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "Status": {
          "$ref": "#/$defs/DockerServerStatus"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "ComputeType",
        "SecurityGroupIds",
        "Status"
      ]
    },
    "DockerServerStatus": {
      "properties": {
        "Message": {
          "type": "string"
        },
        "Status": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Message",
        "Status"
      ]
    },
    "EnvironmentVariable": {
      "properties": {
        "Name": {
          "type": "string"
        },
        "Value": {
          "type": "string"
        },
        "Type": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Name",
        "Value",
        "Type"
      ]
    },
    "ExportedEnvironmentVariable": {
      "properties": {
        "Name": {
          "type": "string"
        },
        "Value": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Name",
        "Value"
      ]
    },
    "GitSubmodulesConfig": {
      "properties": {
        "FetchSubmodules": {
          "type": "boolean"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "FetchSubmodules"
      ]
    },
    "LogsLocation": {
      "properties": {
        "CloudWatchLogs": {
          "$ref": "#/$defs/CloudWatchLogsConfig"
        },
        "CloudWatchLogsArn": {
          "type": "string"
        },
        "DeepLink": {
          "type": "string"
        },
        "GroupName": {
          "type": "string"
        },
        "S3DeepLink": {
          "type": "string"
        },
        "S3Logs": {
          "$ref": "#/$defs/S3LogsConfig"
        },
        "S3LogsArn": {
          "type": "string"
        },
        "StreamName": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "CloudWatchLogs",
        "CloudWatchLogsArn",
        "DeepLink",
        "GroupName",
        "S3DeepLink",
        "S3Logs",
        "S3LogsArn",
        "StreamName"
      ]
    },
    "NetworkInterface": {
      "properties": {
        "NetworkInterfaceId": {
          "type": "string"
        },
        "SubnetId": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "NetworkInterfaceId",
        "SubnetId"
      ]
    },
    "PhaseContext": {
      "properties": {
        "Message": {
          "type": "string"
        },
        "StatusCode": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Message",
        "StatusCode"
      ]
    },
    "ProjectCache": {
      "properties": {
        "Type": {
          "type": "string"
        },
        "CacheNamespace": {
          "type": "string"
        },
        "Location": {
          "type": "string"
        },
        "Modes": {
          "items": {
            "type": "string"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Type",
        "CacheNamespace",
        "Location",
        "Modes"
      ]
    },
    "ProjectEnvironment": {
      "properties": {
        "ComputeType": {
          "type": "string"
        },
        "Image": {
          "type": "string"
        },
        "Type": {
          "type": "string"
        },
        "Certificate": {
          "type": "string"
        },
        "ComputeConfiguration": {
          "$ref": "#/$defs/ComputeConfiguration"
        },
        "DockerServer": {
          "$ref": "#/$defs/DockerServer"
        },
        "EnvironmentVariables": {
          "items": {
            "$ref": "#/$defs/EnvironmentVariable"
          },
          "type": "array"
        },
        "Fleet": {
          "$ref": "#/$defs/ProjectFleet"
        },
        "ImagePullCredentialsType": {
          "type": "string"
        },
        "PrivilegedMode": {
          "type": "boolean"
        },
        "RegistryCredential": {
          "$ref": "#/$defs/RegistryCredential"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "ComputeType",
        "Image",
        "Type",
        "Certificate",
        "ComputeConfiguration",
        "DockerServer",
        "EnvironmentVariables",
        "Fleet",
        "ImagePullCredentialsType",
        "PrivilegedMode",
        "RegistryCredential"
      ]
    },
    "ProjectFileSystemLocation": {
      "properties": {
        "Identifier": {
          "type": "string"
        },
        "Location": {
          "type": "string"
        },
        "MountOptions": {
          "type": "string"
        },
        "MountPoint": {
          "type": "string"
        },
        "Type": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Identifier",
        "Location",
        "MountOptions",
        "MountPoint",
        "Type"
      ]
    },
    "ProjectFleet": {
      "properties": {
        "FleetArn": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "FleetArn"
      ]
    },
    "ProjectSource": {
      "properties": {
        "Type": {
          "type": "string"
        },
        "Auth": {
          "$ref": "#/$defs/SourceAuth"
        },
        "BuildStatusConfig": {
          "$ref": "#/$defs/BuildStatusConfig"
        },
        "Buildspec": {
          "type": "string"
        },
        "GitCloneDepth": {
          "type": "integer"
        },
        "GitSubmodulesConfig": {
          "$ref": "#/$defs/GitSubmodulesConfig"
        },
        "InsecureSsl": {
          "type": "boolean"
        },
        "Location": {
          "type": "string"
        },
        "ReportBuildStatus": {
          "type": "boolean"
        },
        "SourceIdentifier": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Type",
        "Auth",
        "BuildStatusConfig",
        "Buildspec",
        "GitCloneDepth",
        "GitSubmodulesConfig",
        "InsecureSsl",
        "Location",
        "ReportBuildStatus",
        "SourceIdentifier"
      ]
    },
    "ProjectSourceVersion": {
      "properties": {
        "SourceIdentifier": {
          "type": "string"
        },
        "SourceVersion": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "SourceIdentifier",
        "SourceVersion"
      ]
    },
    "RegistryCredential": {
      "properties": {
        "Credential": {
          "type": "string"
        },
        "CredentialProvider": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Credential",
        "CredentialProvider"
      ]
    },
    "S3LogsConfig": {
      "properties": {
        "Status": {
          "type": "string"
        },
        "BucketOwnerAccess": {
          "type": "string"
        },
        "EncryptionDisabled": {
          "type": "boolean"
        },
        "Location": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Status",
        "BucketOwnerAccess",
        "EncryptionDisabled",
        "Location"
      ]
    },
    "SourceAuth": {
      "properties": {
        "Type": {
          "type": "string"
        },
        "Resource": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "Type",
        "Resource"
      ]
    },
    "VpcConfig": {
      "properties": {
        "SecurityGroupIds": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "Subnets": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "VpcId": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "SecurityGroupIds",
        "Subnets",
        "VpcId"
      ]
    }
  }
}
```
