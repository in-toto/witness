![witness](/docs/assets/logo.png)

## Witness is a pluggable framework for supply chain security

Witness prevents tampering of build materials and verifies the integrity of the build process from source to target.  It works by wrapping commands executed in a continuous integration process.  Its attestation system is pluggable and offers support out of the box for most major CI and infrastructure providers.  Verification of Witness metadata and a secure PKI distribution system will mitigate against many supply chain attack vectors.

- Records secure hashes of materials, artifacts, and events occurring during the CI process
- Integrations with cloud identity services
- Keyless signing with SPIFFE/SPIRE
- Support for uploading attestation evidence to rekor server (sigstore)
- Build policy enforcement with Open Policy Agent.

## Getting Started

```
curl -LO https://github.com/testifysec/witness/releases/download/${VERSION}/witness_${VERSION}_${ARCH}.tar.gz
tar -xzf witness_${VERSION}_${ARCH}.tar.gz

openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem

./witness run -s build -k testkey.pem -o attestation.json -- \
  go build .

cat attestation.json | jq -r .payload | base64 -d | jq

```

## Usage

- [Run](docs/witness_run.md) - Runs the provided command and records attestations about the execution.
- [Sign](docs/witness_sign.md) - Signs the provided file with the provided key.
- [Verify](docs/witness_verify.md) - Verifies a witness policy.

## Attestors

- [AWS](docs/attestor.md#aws) - Attestor for AWS Instance Metadata
- [GCP](docs/attestor.md#gcp) - Attestor for GCP Instance Idenity Service
- [GitLab](docs/attestor.md#gitlab) - Attestor for GitLab Pipelines
- [GitHub](docs/attestor.md#github) - Attestor for GitHub Actions
- [CommandRun](docs/attestor.md#commandrun) - Attestor for running a command
- [Artifact](docs/attestor.md#artifact) - Attestor for uploading artifacts
- [Environment](docs/attestor.md#environment) - Attestor for environment variables
- [Git](docs/attestor.md#git) - Attestor for Git Repository

## Support

[TestifySec](https://testifysec.com) Provides support for witness and other CI security tools.
[Contact Us](mailto:info@testifysec.com)
