# Jenkins Attestor

The [Jenkins](https://www.jenkins.io/) Attestor records information about the Jenkins CI/CD job execution in which
Witness was run.

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "buildid": {
          "type": "string"
        },
        "buildnumber": {
          "type": "string"
        },
        "buildtag": {
          "type": "string"
        },
        "pipelineurl": {
          "type": "string"
        },
        "executornumber": {
          "type": "string"
        },
        "javahome": {
          "type": "string"
        },
        "jenkinsurl": {
          "type": "string"
        },
        "jobname": {
          "type": "string"
        },
        "nodename": {
          "type": "string"
        },
        "workspace": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "buildid",
        "buildnumber",
        "buildtag",
        "pipelineurl",
        "executornumber",
        "javahome",
        "jenkinsurl",
        "jobname",
        "nodename",
        "workspace"
      ]
    }
  }
}
```
