# Attestors

A Witness attestor is a programming interface that defines an object that can assert facts about a system and store those facts in a versioned schema. An attestor has a `Name`, `Type` and `RunType`. The `Type` is a versioned string corresponding to the JSON schema of the attestation. For example, the AWS attestor is defined as follows:
```
  Name    = "aws"
  Type    = "https://witness.dev/attestations/aws/v0.1"
  RunType = attestation.PreRunType
```
Attestation types are leveraged to ensure the correct version schema is used when we evaluate policy against these attestations.

## Attestor Security Model

Attestations are only as secure as the data that feeds them. Where possible cryptographic material should be validated, evidence of validation should be included in the attestation for out-of-band validation.

Examples of cryptographic validation is found in the [GCP](https://github.com/in-toto/go-witness/tree/main/attestation/gcp-iit), [AWS](https://github.com/in-toto/go-witness/tree/main/attestation/aws-iid), and [GitLab](https://github.com/in-toto/go-witness/tree/main/attestation/gitlab) attestors.

## Attestor Life Cycle

- **Pre-material:** Pre-material attestors run before any other attestors. These attestors generally collect information about the environment.

- **Material:** Material attestors run after any prematerial attestors and prior to any execute attestors. Generally these collect information about state that may change after any execute attestors, such as file hashes.

- **Execute:**: Execute attestors run after any material attestors and generally record information about some command or process that is to be executed.

- **Product:** Product attestors run after any execute attestors and generally record information about what changed during the execute lifecycle step, such as changed or created files.

- **Post-product:** Post-product attestors run after product attestors and generally record some additional information about specific products, such as OCI image information from a saved image tarball.
