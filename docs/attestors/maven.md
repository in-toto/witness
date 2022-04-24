# Maven Attestor

The Maven Attestor records project and dependency information from a provided pom.xml ([Maven Project Object Model](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html)).

## Subjects

| Subject | Description |
| ------- | ----------- |
| `project:group/artifact@version` | The group, artifact, and version of the project to which the pom.xml belongs |
| `dependency:group/artifact@version` | The group, artifact, and verion of each dependency in the pom.xml |
