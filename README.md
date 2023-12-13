# Witness [![Go Reference](https://pkg.go.dev/badge/github.com/in-toto/witness.svg)](https://pkg.go.dev/github.com/in-toto/witness) [![Go Report Card](https://goreportcard.com/badge/github.com/in-toto/witness)](https://goreportcard.com/report/github.com/in-toto/witness) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8164/badge)](https://www.bestpractices.dev/projects/8164) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/in-toto/witness/badge)](https://securityscorecards.dev/viewer/?uri=github.com/in-toto/witness)

<div align="center" >
   
**[DOCS](https://witness.dev) • 
[CONTRIBUTING](./CONTRIBUTORS.md) • 
[LICENSE](./LICENSE)**  
<span style="font-size:0.9em;"> **Get Started Now 👇** </span><br>
<span style="font-size:0.85em;">`bash <(curl -s https://raw.githubusercontent.com/in-toto/witness/main/install-witness.sh)`</span><br><br>
</div>

<img src="docs/assets/logo.png" align="right"
     alt="Witness project logo" width="150">

### What does Witness do?<br>
✏️ **Attests** - <span style="font-size:0.9em;">Witness is a dynamic CLI tool that integrates into pipelines and infrastructure to create an audit trail for your software's entire journey through the software development lifecycle (SDLC) using the in-toto specification.</span><br>

**🧐 Verifies** - <span style="font-size:0.9em;">Witness also features its own policy engine with embedded support for OPA Rego, so you can ensure that your software was handled safely from source to deployment.</span>

### What can you do with Witness?
- Verify how your software was produced and what tools were used
- Ensure that each step of the supply chain was completed by authorized users and machines
- Detect potential tampering or malicious activity
- Distribute attestations and policy across air gaps

### Key Features
 - Integrations with GitLab, GitHub, AWS, and GCP.
 - Designed to run in both containerized and non-containerized environments **without** elevated privileges.
 - Implements the in-toto specification (including ITE-5, ITE-6 and ITE-7)
 - An embedded OPA Rego policy engine for policy enforcement
 - Keyless signing with Sigstore and SPIFFE/SPIRE
 - Integration with RFC3161 compatible timestamp authorities
 - Process tracing and process tampering prevention (Experimental)
- Attestation storage with [Archivista](https://github.com/in-toto/archivista)

### Demo
![Demo][demo]

## Quick Start

### Installation
To install Witness, all you will need is the Witness binary. You can download this from the [releases]
(https://github.com/testifysec/witness/releases) page or use the install script to download the
latest release:
```
bash <(curl -s https://raw.githubusercontent.com/in-toto/witness/main/install-witness.sh)
```

### Tutorial
This quick tutorial will walk you through a simple example of how Witness can be used. To complete it
successfully, you will need the following:
* [Go](https://go.dev/doc/install) (1.19 or later is recommended)
* [openssl](https://www.openssl.org/)
* [jq](https://jqlang.github.io/jq/)
* [base64](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html) (which is part of GNU coreutils)

1. Create a Keypair

>💡 Tip: Witness supports keyless signing with [SPIRE](https://spiffe.io/)!

```
openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem
```

2. Create a Witness configuration
><span style="font-size:0.9em;">💡 Tip: Witness supports creating attestations for a wide variety of services,
  including Github Actions </span>

- This file generally resides in your source code repository along with the public keys generated above.
- `.witness yaml` is the default location for the configuration file
- `witness help` will show all configuration options
- command-line arguments overrides configuration file values.

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

3. Record attestations for a build step
><span style="font-size:0.9em;">💡 Tip: You can upload the recorded attestations to an [Archivista](https://github.com/in-toto/archivista) server by using the `--enable-archivista` flag!</span>
- The `-a {attestor}` flag allows you to define which attestors run
- ex. `-a maven -a gcp -a gitlab` would be used for a maven build running on a GitLab runner on GCP.
- Defining step names is important, these will be used in the policy.
- This should happen as a part of a CI step

```
witness run --step build -o test-att.json -- go build -o=testapp .
```

4. View the attestation data in the signed DSSE Envelope

- This data can be stored and retrieved from Archivista
- This is the data that is evaluated against the Rego policy

```
cat test-att.json | jq -r .payload | base64 -d | jq
```

5. Create a Policy File

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

6. Replace the variables in the policy

```
id=`sha256sum testpub.pem | awk '{print $1}'` && sed -i "s/{{PUBLIC_KEY_ID}}/$id/g" policy.json
pubb64=`cat testpub.pem | base64 -w 0` && sed -i "s/{{B64_PUBLIC_KEY}}/$pubb64/g" policy.json
```

7. Sign The Policy File

Keep this key safe, its owner will control the policy gates.

```
witness sign -f policy.json --signer-file-key-path testkey.pem --outfile policy-signed.json
```

8. Verify the Binary Meets Policy Requirements

> This process works across air-gap as long as you have the signed policy file, correct binary, and public key or certificate authority corresponding to the private key that signed the policy.
> `witness verify` will return a `non-zero` exit and reason in the case of failure. Success will be silent with a `0` exit status
> for policies that require multiple steps, multiple attestations are required.

```
witness verify -f testapp -a test-att.json -p policy-signed.json -k testpub.pem
```

### Check out our other tutorials
###### [Verify an Artifact Policy](https://github.com/testifysec/witness-examples/blob/main/keypair/README.md)
###### [Using Fulcio as a Key Provider](https://github.com/testifysec/witness-examples/blob/main/keyless-fulcio/README.md)

## How does Witness work?
### Signing
Witness is able to observe your software development life-cycle (SDLC) by wrapping around commands executed within them. By passing any command to Witness as an argument, the tool is able to understand what was executed but also on what infrastructure, by what user or service account and more. The information that Witness gathers while the command is running is down to which [Attestors](docs/attestor.md) are used. Attestors are implementations of an interface that find and assert facts about the system Witness is running on (e.g., [AWS Attestor](docs/attestors/aws-iid.md)). Finally, Witness can compile this information into an [in-toto attestation](https://github.com/in-toto/attestation), place it in a [DSSE Envelope](https://github.com/secure-systems-lab/dsse) and sign that envelope with the key that was supplied by the user. 

### Storing
For storage, the Witness project can upload signed attestations to an [Archivista](https://github.com/in-toto/archivista) server, a graph and storage service for in-toto attestations. This enables the discovery and retrieval of attestations for verification of software artifacts.

### Verifying
Witness allows users to verify the attestations that they generate by providing the `witness verify` command. To achieve this, Witness uses a [policy file](./docs/policy.md) defined by the user to check for presence of the expected attestations and that they were signed by the appropriate functionaries (Public keys or roots of trust that are trusted to sign certain types of attestation). To verify the attestation body itself, Witness supports defining [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies inside the policy file. This allows users to ensure the facts asserted by the Attestors are reported expected.

# Media
Check out some of the content out in the wild that gives more detail on how the project can be used.

- [Blog/Video - Generating and Verifying Attestations With Witness](https://www.testifysec.com/blog/attestations-with-witness/)
- [Blog - What is a supply chain attestation, and why do I need it?](https://www.testifysec.com/blog/what-is-a-supply-chain-attestation/)
- [Talk - Securing the Software Supply Chain with the in-toto & SPIRE projects](https://www.youtube.com/watch?v=4lFbdkB62QI)
- [Talk - Securing the Software Supply Chain with SBOM and Attestation](https://www.youtube.com/watch?v=wX6aTZfpJv0)

[demo]: docs/assets/demo.gif "Demo"
