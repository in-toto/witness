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
          "type": "string",
          "title": "Group ID",
          "description": "Maven group identifier for the project"
        },
        "artifactid": {
          "type": "string",
          "title": "Artifact ID",
          "description": "Maven artifact identifier for the project"
        },
        "version": {
          "type": "string",
          "title": "Version",
          "description": "Project version"
        },
        "projectname": {
          "type": "string",
          "title": "Project Name",
          "description": "Human-readable project name"
        },
        "dependencies": {
          "items": {
            "$ref": "#/$defs/MavenDependency"
          },
          "type": "array",
          "title": "Dependencies",
          "description": "List of Maven dependencies"
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
          "type": "string",
          "title": "Group ID",
          "description": "Dependency group identifier"
        },
        "artifactid": {
          "type": "string",
          "title": "Artifact ID",
          "description": "Dependency artifact identifier"
        },
        "version": {
          "type": "string",
          "title": "Version",
          "description": "Dependency version"
        },
        "scope": {
          "type": "string",
          "title": "Scope",
          "description": "Dependency scope (compile test runtime etc)"
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
