# Environment Dependencies Policy

## Purpose

This policy describes how Witness maintainers consume third-party packages.

## Scope

This policy applies to all Witness maintainers and all third-party packages used in the Witness project.

## Policy

Witness maintainers must follow these guidelines when consuming third-party packages:

- Only use third-party packages that are necessary for the functionality of Witness.
- Use the latest version of all third-party packages whenever possible.
- Avoid using third-party packages that are known to have security vulnerabilities.
- Pin all third-party packages to specific versions in the Witness codebase.
- Use a dependency management tool, such as Go modules, to manage third-party dependencies.

## Procedure

When adding a new third-party package to Witness, maintainers must follow these steps:

1. Evaluate the need for the package. Is it necessary for the functionality of Witness?
2. Research the package. Is it well-maintained? Does it have a good reputation?
3. Choose a version of the package. Use the latest version whenever possible.
4. Pin the package to the specific version in the Witness codebase.
5. Update the Witness documentation to reflect the new dependency.

## Enforcement

This policy is enforced by the Witness maintainers.
Maintainers are expected to review each other's code changes to ensure that they comply with this policy.

## Exceptions

Exceptions to this policy may be granted by the Witness project lead on a case-by-case basis.

## Credits

This policy was adapted from the [Kubescape Community](https://github.com/kubescape/kubescape/blob/master/docs/environment-dependencies-policy.md)
