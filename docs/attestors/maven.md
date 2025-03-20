# Maven Attestor

The [Maven](https://maven.apache.org/) Attestor records project and dependency information from a provided pom.xml ([Maven Project Object Model](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html)).

## Subjects

| Subject | Description |
| ------- | ----------- |
| `project:group/artifact@version` | The group, artifact, and version of the project to which the pom.xml belongs |
| `dependency:group/artifact@version` | The group, artifact, and version of each dependency in the pom.xml |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "groupid": {
          "type": "string"
        },
        "artifactid": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "projectname": {
          "type": "string"
        },
        "dependencies": {
          "items": {
            "$ref": "#/$defs/MavenDependency"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "groupid",
        "artifactid",
        "version",
        "projectname",
        "dependencies"
      ]
    },
    "MavenDependency": {
      "properties": {
        "groupid": {
          "type": "string"
        },
        "artifactid": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "scope": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "groupid",
        "artifactid",
        "version",
        "scope"
      ]
    }
  }
}
```
