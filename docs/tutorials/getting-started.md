---
sidebar_position: 0
---
# Getting Started

## Intro

This quick tutorial will walk you through a simple example of how Witness can be used. To complete it
successfully, you will need the following:

- [Go](https://go.dev/doc/install) (1.19 or later is recommended)
- [openssl](https://www.openssl.org/)
- [jq](https://jqlang.github.io/jq/)
- [base64](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html) (which is part of GNU coreutils)

You will also of course need to have witness installed, which can be achieved by following the [Quick Start](/README.md#quick-start).

## Let's Go!

### 1. Create a Keypair

><span class="tip-text">💡 Tip: Witness supports keyless signing with [SPIRE](https://spiffe.io/)!</span>

```shell
openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem
```

### 2. Create a Witness Configuration

><span class="tip-text">💡 Tip: Witness supports creating attestations for a wide variety of services,
> including Github Actions </span>

- This file generally resides in your source code repository along with the public keys generated above.
- `.witness.yaml` is the default location for the configuration file
- `witness help` will show all configuration options
- command-line arguments overrides configuration file values.

```yaml
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

### 3. Record attestations for a build step

><span class="tip-text">💡 Tip: You can upload the recorded attestations to an [Archivista](https://github.com/in-toto/archivista) server by using the `--enable-archivista` flag!</span>

- The `-a {attestor}` flag allows you to define which attestors run
- ex. `-a maven -a gcp -a gitlab` would be used for a maven build running on a GitLab runner on GCP.
- Witness has a set of attestors that are always run. You can see them in the output of the `witness attestors list` command.
- Defining step names is important, these will be used in the policy.
- This should happen as a part of a CI step

```shell
witness run --step build -o test-att.json -a slsa --attestor-slsa-export -- go build -o=testapp .
```

><span class="tip-text">💡 Tip: When you run a step with many files as the product of that step, like node_modules, it could be beneficial to collapse the result into a hash of the directory content. You can use `--dirhash-glob <glob-pattern>` to match the directory or use it multiple times to use different glob patterns. E.g. `--dirhash-glob node_modules/*`</span>

><span class="tip-text">💡 Tip: The `-a slsa` option allows to generate the [SLSA Provenace](https://slsa.dev/spec/v1.0/provenance) predicate in the attestation. The `--attestor-slsa-export` option allows to write the Provenance in a dedicated file. This is a mandatory requirement for SLSA Level 1</span>

### 4. View the attestation data in the signed DSSE Envelope

- This data can be stored and retrieved from Archivista
- This is the data that is evaluated against the Rego policy

```shell
cat test-att.json | jq -r .payload | base64 -d | jq
```

### 5. Create a Policy File

Look [here](/docs/concepts/policy.md) for full documentation on Witness Policies.

> - Make sure to replace the keys in this file with the ones from the step above (sed command below).
> - Rego policies should be base64 encoded
> - Steps are bound to keys. Policy can be written to check the certificate data. For example, we can require a step is signed by a key with a specific `CN` attribute.
> - Witness will require all attestations to succeed
> - Witness will evaluate the rego policy against the JSON object in the corresponding attestor

```json
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

### 6. Replace the variables in the policy

```shell
id=`sha256sum testpub.pem | awk '{print $1}'` && sed -i "s/{{PUBLIC_KEY_ID}}/$id/g" policy.json
pubb64=`cat testpub.pem | base64 -w 0` && sed -i "s/{{B64_PUBLIC_KEY}}/$pubb64/g" policy.json
```

### 7. Sign The Policy File

Keep this key safe, its owner will control the policy gates.

```shell
witness sign -f policy.json --signer-file-key-path testkey.pem --outfile policy-signed.json
```

### 8. Verify the Binary Meets Policy Requirements

This process works across air-gap as long as you have the signed policy file, correct binary, and public key or certificate authority corresponding to the private key that signed the policy.

```shell
witness verify -f testapp -a test-att.json -p policy-signed.json -k testpub.pem
```

If you want to verify a directory as a subject you can use the following.

```shell
witness verify --directory-path node_modules/example -a test-att.json -p policy-signed.json -k testpub.pem
```

### 9. Profit

`witness verify` will return a `non-zero` exit and reason in the case of failure, but hopefully you should have gotten sweet sweet silence with a `0` exit status, victory! If not, try again and if that fails please [file an issue](https://github.com/in-toto/witness/issues/new/choose)!

## What's Next?

If you enjoyed this intro to Witness, you might benefit from taking things a step further by learning about [Witness Policies](./artifact-policy.md).
