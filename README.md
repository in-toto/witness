[![OpenSSF
-Scorecard](https://api.securityscorecards.dev/projects/github.com/testifysec/witness/badge)](https://api.securityscorecards.dev/projects/github.com/testifysec/witness)

<p align="center">
  <img src="docs/assets/logo.png" width="250">
  <br>
  Witness is a pluggable framework for supply chain security
</p>

[![asciicast](https://asciinema.org/a/2DZRRh8uzrzHcUVL8md86Zj4D.svg)](https://asciinema.org/a/2DZRRh8uzrzHcUVL8md86Zj4D)

# Witness - Secure Your Supply Chain

Witness is a pluggable framework for supply chain security that creates an evidence trail of the entire software development life cycle (SDLC) to ensure the integrity of your software from source to target. It supports most major CI and infrastructure providers, and uses a secure PKI distribution system to enhance security and mitigate against software supply chain attack vectors.

Witness works by wrapping commands executed in a continuous integration process, providing an evidence trail of every action in the software development life cycle (SDLC). This allows for a detailed and verifiable record of how the software was built, who built it, and what tools were used. This evidence can be used to evaluate policy compliance and detect any potential tampering or malicious activity and ensure only authorized users or machines completes a step of the process. Additionally, Witness's attestation system is pluggable and offers support for most major CI and infrastructure providers, making it a versatile and flexible solution for securing software supply chains. Furthermore, the use of a secure PKI distribution system and the ability to verify Witness metadata further enhances the security of the process and helps mitigate against many software supply chain attack vectors.

**NOTE:** the attestor code has been split into repo https://github.com/testifysec/go-witness

## Witness enables you to:

- Verify who built the software, how it was built and what tools were used
- Detect any potential tampering or malicious activity
- Ensure that only authorized users or machines complete each step of the process
- Distribute attestations and policy across air gaps

## Witness is a pluggable framework for supply chain security

 - It creates an evidence trail of the entire software development life cycle (SDLC) that can be used to evaluate policy compliance and detect any potential tampering or malicious activity.
 - It is designed to run in both containerized and non-containerized environments and does not require elevated privileges.
 - It supports most major CI and infrastructure providers, making it a versatile and flexible solution for securing software supply chains.
 - It uses a secure PKI distribution system and allows for verification of Witness metadata to further enhance security and mitigate against software supply chain attack vectors.

## Key Features
 - Implementation of the in-toto specification including ITE-5, ITE-6, and ITE-7, and an embedded rego policy engine for build policy enforcement.
 - Support for keyless signing with Sigstore and SPIFFE/SPIRE, and uploading attestation evidence to the Archivista server.
 - Support for RFC3161 compatible timestamp authorities
 - Experimental support for process tracing and process tampering prevention.
 - Verifies file integrity between CI steps and across air gap.
 - Support for Darwin, Windows, and ARM architectures.
 - Can use Archivista as an attestation store.
 - Integrations with GitLab, GitHub, AWS, and GCP.

## How it works
- Witness wraps commands executed during a continuous integration process to create an evidence trail of the entire software development life cycle (SDLC)
- It records secure hashes of materials, artifacts, and events that occur during the CI process
- This evidence can be used to evaluate policy compliance, detect tampering or malicious activity, and ensure only authorized users or machines complete a step of the process
- Witness's attestation system is pluggable and supports most major CI and infrastructure providers
- It uses a secure PKI distribution system and can verify Witness metadata to enhance security and mitigate against many software supply chain attack vectors
- Witness is an implementation of the in-toto specification, including ITE-5, ITE-6, and ITE-7, and includes an embedded rego policy engine for build policy enforcement with Open Policy Agent
- It can run in both containerized and non-containerized environments without requiring elevated privileges
- It supports keyless signing with Sigstore and SPIFFE/SPIRE and uploading attestation evidence to the [Archivista](https://github.com/testifysec/archivista) server
- It offers experimental support for tracing and process tampering prevention and can verify file integrity between CI steps and across air gap
- It supports Darwin, Windows, and ARM architectures and can use [Archivista](https://github.com/testifysec/archivista) as an attestation store
- Overall, Witness acts as a comprehensive framework for automated governance, providing a robust solution for securing the software supply chain.


## Witness Examples

- [Verify an Artifact Policy](https://github.com/testifysec/witness-examples/blob/main/keypair/README.md)
- [Using Fulcio as a Key Provider](https://github.com/testifysec/witness-examples/blob/main/keyless-fulcio/README.md)

## Media

- [Blog/Video - Generating and Verifying Attestations With Witness](https://www.testifysec.com/blog/attestations-with-witness/)
- [Blog - What is a supply chain attestation, and why do I need it?](https://www.testifysec.com/blog/what-is-a-supply-chain-attestation/)
- [Talk - Securing the Software Supply Chain with the in-toto & SPIRE projects](https://www.youtube.com/watch?v=4lFbdkB62QI)
- [Talk - Securing the Software Supply Chain with SBOM and Attestation](https://www.youtube.com/watch?v=wX6aTZfpJv0)

## Usage

- [Run](docs/witness_run.md) - Runs the provided command and records attestations about the execution.
- [Sign](docs/witness_sign.md) - Signs the provided file with the provided key.
- [Verify](docs/witness_verify.md) - Verifies a witness policy.

## TOC

- [Witness - Secure Your Supply Chain](#witness---secure-your-supply-chain)
  - [Witness enables you to:](#witness-enables-you-to)
  - [Witness is a pluggable framework for supply chain security](#witness-is-a-pluggable-framework-for-supply-chain-security)
  - [Key Features](#key-features)
  - [How it works](#how-it-works)
  - [Witness Examples](#witness-examples)
  - [Media](#media)
  - [Usage](#usage)
  - [TOC](#toc)
  - [Quick Start](#quick-start)
    - [Download the Binary](#download-the-binary)
    - [Create a Keypair](#create-a-keypair)
    - [Create a Witness configuration](#create-a-witness-configuration)
    - [Record attestations for a build step](#record-attestations-for-a-build-step)
    - [View the attestation data in the signed DSSE Envelope](#view-the-attestation-data-in-the-signed-dsse-envelope)
    - [Create a Policy File](#create-a-policy-file)
    - [Replace the variables in the policy](#replace-the-variables-in-the-policy)
    - [Sign The Policy File](#sign-the-policy-file)
    - [Verify the Binary Meets Policy Requirements](#verify-the-binary-meets-policy-requirements)
- [Witness Attestors](#witness-attestors)
  - [What is a witness attestor?](#what-is-a-witness-attestor)
  - [Attestor Security Model](#attestor-security-model)
  - [Attestor Life Cycle](#attestor-life-cycle)
    - [Attestation Lifecycle](#attestation-lifecycle)
  - [Attestor Types](#attestor-types)
    - [Pre-material Attestors](#pre-material-attestors)
    - [Material Attestors](#material-attestors)
    - [Execute Attestors](#execute-attestors)
    - [Product Attestors](#product-attestors)
    - [Post-product Attestors](#post-product-attestors)
    - [AttestationCollection](#attestationcollection)
    - [Attestor Subjects](#attestor-subjects)
  - [Witness Policy](#witness-policy)
    - [What is a witness policy?](#what-is-a-witness-policy)
  - [Witness Verification](#witness-verification)
    - [Verification Lifecycle](#verification-lifecycle)
  - [Using SPIRE for Keyless Signing](#using-spire-for-keyless-signing)
  - [Support](#support)

## Quick Start

### Download the Binary
Download from the releases page or use the install script to download the latest release.

[Releases](https://github.com/testifysec/witness/releases)
```
bash <(curl -s https://raw.githubusercontent.com/testifysec/witness/main/install-witness.sh)
```


### Create a Keypair

> Witness supports keyless signing with [SPIRE](https://spiffe.io/)!

```
openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem
```

### Create a Witness configuration

> - This file generally resides in your source code repository along with the public keys generated above.
> - `.witness yaml` is the default location for the configuration file
> - `witness help` will show all configuration options
> - command-line arguments overrides configuration file values.

```
## .witness.yaml

run:
    signer-file-key-path: testkey.pem
    trace: false
verify:
    attestations:
        - "test-att.json"
    policy: policy-signed.json
    publickey: testpub.pem
```

### Record attestations for a build step

> - The `-a {attestor}` flag allows you to define which attestors run
> - ex. `-a maven -a gcp -a gitlab` would be used for a maven build running on a GitLab runner on GCP.
> - Defining step names is important, these will be used in the policy.
> - This should happen as a part of a CI step

```
witness run --step build -o test-att.json -- go build -o=testapp .
```

### View the attestation data in the signed DSSE Envelope

> - This data can be stored and retrieved from Archivista
> - This is the data that is evaluated against the Rego policy

```
cat test-att.json | jq -r .payload | base64 -d | jq
```

### Create a Policy File

Look [here](docs/policy.md) for full documentation on Witness Policies.

> - Make sure to replace the keys in this file with the ones from the step above (sed command below).
> - Rego policies should be base64 encoded
> - Steps are bound to keys. Policy can be written to check the certificate data. For example, we can require a step is signed by a key with a specific `CN` attribute.
> - Witness will require all attestations to succeed
> - Witness will evaluate the rego policy against the JSON object in the corresponding attestor

```
## policy.json

{
  "expires": "2023-12-17T23:57:40-05:00",
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.dev/attestations/command-run/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.dev/attestations/product/v0.1",
          "regopolicies": []
        }
      ],
      "functionaries": [
        {
          "publickeyid": "{{PUBLIC_KEY_ID}}"
        }
      ]
    }
  },
  "publickeys": {
    "{{PUBLIC_KEY_ID}}": {
      "keyid": "{{PUBLIC_KEY_ID}}",
      "key": "{{B64_PUBLIC_KEY}}"
    }
  }
}
```

### Replace the variables in the policy

```
id=`sha256sum testpub.pem | awk '{print $1}'` && sed -i "s/{{PUBLIC_KEY_ID}}/$id/g" policy.json
pubb64=`cat testpub.pem | base64 -w 0` && sed -i "s/{{B64_PUBLIC_KEY}}/$pubb64/g" policy.json
```

### Sign The Policy File

Keep this key safe, its owner will control the policy gates.

```
witness sign -f policy.json --key testkey.pem --outfile policy-signed.json
```

### Verify the Binary Meets Policy Requirements

> This process works across air-gap as long as you have the signed policy file, correct binary, and public key or certificate authority corresponding to the private key that signed the policy.
> `witness verify` will return a `non-zero` exit and reason in the case of failure. Success will be silent with a `0` exit status
> for policies that require multiple steps, multiple attestations are required.

```
witness verify -f testapp -a test-att.json -p policy-signed.json -k testpub.pem
```

# Witness Attestors

## What is a witness attestor?

Witness attestors are pieces of code that assert facts about a system and store those facts in a versioned schema. Each attestor has a `Name`, `Type`, and `RunType`. The `Type` is a versioned string corresponding to the JSON schema of the attestation. For example, the AWS attestor is defined as follows:

```
  Name    = "aws"
  Type    = "https://witness.dev/attestations/aws/v0.1"
  RunType = attestation.PreRunType
```

The attestation types are used when we evaluate policy against these attestations.

## Attestor Security Model

Attestations are only as secure as the data that feeds them. Where possible cryptographic material should be validated, evidence of validation should be included in the attestation for out-of-band validation.

Examples of cryptographic validation is found in the [GCP](https://github.com/testifysec/witness/tree/main/pkg/attestation/gcp-iit), [AWS](https://github.com/testifysec/witness/blob/main/pkg/attestation/aws-iid/aws-iid.go), and [GitLab](https://github.com/testifysec/witness/tree/main/pkg/attestation/gitlab) attestors.

## Attestor Life Cycle

- **Pre-material:** Pre-material attestors run before any other attestors. These attestors generally collect information about the environment.

- **Material:** Material attestors run after any prematerial attestors and prior to any execute attestors. Generally these collect information about state that may change after any execute attestors, such as file hashes.

- **Execute:**: Execute attestors run after any material attestors and generally record information about some command or process that is to be executed.

- **Product:** Product attestors run after any execute attestors and generally record information about what changed during the execute lifecycle step, such as changed or created files.

- **Post-product:** Post-product attestors run after product attestors and generally record some additional information about specific products, such as OCI image information from a saved image tarball.

### Attestation Lifecycle

![](docs/assets/attestation.png)

## Attestor Types

### Pre-material Attestors
- [AWS](docs/attestors/aws-iid.md) - Attestor for AWS Instance Metadata
- [GCP](docs/attestors/gcp-iit.md) - Attestor for GCP Instance Identity Service
- [GitLab](docs/attestors/gitlab.md) - Attestor for GitLab Pipelines
- [Git](docs/attestors/git.md) - Attestor for Git Repository
- [Maven](docs/attestors/maven.md) Attestor for Maven Projects
- [Environment](docs/attestors/environment.md) - Attestor for environment variables (**_be careful with this - there is no way to mask values yet_**)
- [JWT](docs/attestors/jwt.md) - Attestor for JWT Tokens

### Material Attestors
- [Material](docs/attestors/material.md) - Records secure hashes of files in current working directory

### Execute Attestors
- [CommandRun](docs/attestors/commandrun.md) - Records traces and metadata about the actual process being run

### Product Attestors
- [Product](docs/attestors/product.md) - Records secure hashes of files produced by commandrun attestor (only detects new files)

### Post-product Attestors

- [OCI](docs/attestors/oci.md) - Attestor for tar'd OCI images

### AttestationCollection

An `attestationCollection` is a collection of attestations that are cryptographically bound together. Because the attestations are bound together, we can trust that they all happened as part of the same attesation life cycle. Witness policy defines which attestations are required.

### Attestor Subjects

Attestors define subjects that act as lookup indexes. The attestationCollection can be looked up by any of the subjects defined by the attestors.

## Witness Policy

### What is a witness policy?

A witness policy is a signed document that encodes the requirements for an artifact to be validated. A witness policy includes public keys for trusted functionaries, which attestations must be found, and rego policy to evaluate against the attestation meta-data.

A witness policy allows administrators to trace the compliance status of an artifact at any point during its lifecycle.

## Witness Verification

### Verification Lifecycle

![](docs/assets/verification.png)

## Using [SPIRE](https://github.com/spiffe/spire) for Keyless Signing

Witness can consume ephemeral keys from a [SPIRE](https://github.com/spiffe/spire) node agent. Configure witness with the flag `--spiffe-socket` to enable keyless signing.

During the verification process witness will use a source of trusted time such as a timestamp from a timestamp authority to make a determination on certificate validity. The SPIRE certificate only needs to remain valid long enough for a timestamp to be created.


## Support

[TestifySec](https://testifysec.com) Provides support for witness and other CI security tools.
[Contact Us](mailto:info@testifysec.com)
