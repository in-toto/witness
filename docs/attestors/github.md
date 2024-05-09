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
          "$ref": "#/$defs/Attestor"
        },
        "ciconfigpath": {
          "type": "string"
        },
        "pipelineid": {
          "type": "string"
        },
        "pipelinename": {
          "type": "string"
        },
        "pipelineurl": {
          "type": "string"
        },
        "projecturl": {
          "type": "string"
        },
        "runnerid": {
          "type": "string"
        },
        "cihost": {
          "type": "string"
        },
        "ciserverurl": {
          "type": "string"
        },
        "runnerarch": {
          "type": "string"
        },
        "runneros": {
          "type": "string"
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
}```
