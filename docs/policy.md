# Policies

Witness policies allow users to make assertions and test attestation collections generated during `witness run`.
Examples of when a policy could be enforced include within a Kubernetes admission controller, at the end of a CI/CD
pipeline, prior to image promotion, or before deployment to an execution environment.

Policies enable the ability to ensure all expected attestations are within a collection and support embedded
[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies to make determinations about the content
of each attestation. Attestation signatures cal be linked to trusted functionaries with embedded public keys or X509
roots of trust.

With these powers combined Witness policies ultimately allow users to automatically make decisions about the
trustworthiness of an artifact. Details of who, how, when, and where an artifact was built are all able to be considered
when evaluating policies.

## Verification Process

`witness verify` will evaluate a set of attestation collections against a policy document. If the attestation
collections satisfy the policy witness will exit with an exit code of 0. Any other exit code indicates an error or
policy failure.

Evaluating a Witness policy involves a few different steps:

1. Verify signatures on collections against publickeys and roots within the policy. Any collections that fail signature
   verification will not be used.
1. Verify the signer of each collection maps to a trusted functionary for the corresponding step in the policy.
1. Verify materials recorded in each collection is consistent with the artifacts (materials + products) of other
   collections as configured by the policy.
1. Verify all rego policies embedded in the policy evaluate successfully against collections.

## Schema

Policies are JSON documents that are signed and wrapped in a DSSE envelope. The DSSE payload type will be 
`https://witness.testifysec.com/policy/v0.1`.

### `policy` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `expires` | string | ISO-8601 formatted time. This defines an expiration time for the policy. Evaluation of expired policies always fail. |
| `roots` | object | Trusted X509 root certificates. Attestations that are signed with a certificate that belong to this root will be trusted. Keys of the object are the root certificate's Key ID, values are a `root` object. |
| `publickeys` | object | Trusted public keys. Attestations that are signed with one of these keys will be trusted. Keys of the object are the public key's Key ID, values are a `publickey` object. |
| `steps` | object | Expected steps that must appear to satisfy the policy. Each step requires an attestation collection with a matching name and the expected attestations. Keys of the object are the step's name, values are a `step` object. |

### `root` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `certificate` | string | Base64 encoded PEM block that describes a valid X509 root certificate. |
| `intermediates` | array of strings | Array of base64 encoded PEM blocks that describe valid X509 intermediate certificates belonging to `certificate` |

### `publickey` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `keyid` | string | sha256sum of the public key |
| `key` | string | Base64 encoded public key |

### `step` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `name` | string | Name of the step. Attestation collections must share this name to be considered. |
| `functionaries` | array of `functionary` objects | Public keys or roots of trust that are trusted to sign attestation collections for this step. |
| `attestations` | array of `attestation` objects | Attestations that are expected to appear in an attestation collection to satisfy this step. |
| `artifactsFrom` | array of strings | Other steps that this step uses artifacts (materials & products) from. |

### `functionary` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `type` | string | Type of functionary. Valid values are "root" or "publickey". |
| `certConstraint` | `certConstraint` object | Object defining constraints about the signer's certificate for "root" functionaries. Only valid if `type` is "root". |
| `publickeyid` | string | Key ID of a public key that is trusted to sign this step. Only valid if `type` is "publickey". |

### `certConstraint` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `roots` | array of strings | Array of Key IDs the signer's certificate must belong to to be trusted. |

### `attestation` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `type` | string | Type reference of an attestation that must appear in a step. |
| `regopolicies` | array of `regopolicy` objects | Rego policies that will be run against the attestation. All must pass. |

### `regopolicy` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `name` | string | Name of the rego policy. Will be reported on failures. |
| `module` | string | Base64 encoded rego module |

Rego modules are expected to output a data with the name of `deny` in the case a rego policy evaluation is failed.
`deny` can be a string or an array of strings and should be populated with a human readable string describing why the
policy was denied. Any other data output by the module will be ignored. An example of a valid rego policy may look like:

```
package commandrun.exitcode

deny[msg] {
	input.exitcode != 0
	msg := "exitcode not 0"
}
```

## Example

```
{
  "expires": "2022-12-17T23:57:40-05:00",
  "steps": {
		"clone": {
			"name": "clone",
      "attestations": [
        {
          "type": "https://witness.testifysec.com/attestations/material/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.testifysec.com/attestations/command-run/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.testifysec.com/attestations/product/v0.1",
          "regopolicies": []
        }
      ],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647"
        }
      ]
		},
    "build": {
      "name": "build",
			"artifactsFrom": ["clone"],
      "attestations": [
        {
          "type": "https://witness.testifysec.com/attestations/material/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.testifysec.com/attestations/command-run/v0.1",
          "regopolicies": [
            {
              "name": "expected command",
              "module": "cGFja2FnZSBjb21tYW5kcnVuLmNtZAoKZGVueVttc2ddIHsKCWlucHV0LmNtZCAhPSBbImdvIiwgImJ1aWxkIiwgIi1vPXRlc3RhcHAiLCAiLiJdCgltc2cgOj0gInVuZXhwZWN0ZWQgY21kIgp9Cg=="
            }
          ]
        },
        {
          "type": "https://witness.testifysec.com/attestations/product/v0.1",
          "regopolicies": []
        }
      ],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647"
        }
      ]
    }
  },
  "publickeys": {
    "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647": {
      "keyid": "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647",
      "key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQWYyOW9QUDhVZ2hCeUc4NTJ1QmRPeHJKS0tuN01NNWhUYlA5ZXNnT1ovazA9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
    }
  }
}
```

The embedded rego policy above is:

```
package commandrun.cmd

deny[msg] {
	input.cmd != ["go", "build", "-o=testapp", "."]
	msg := "unexpected cmd"
}
```

The above example policy requires two attestation collections are present, one named "clone" and one named "build". Both
collections must have a material, command-run, and product attestor within them. The command-run attestor for the
"build" collection must have recorded a command of `go build -o=testapp .` to pass the embedded rego policy. The build
step is configured to ensure the materials used are consistent with the artifacts from the clone step, assuring that
files used during the build process are the same that were produced during the clone step.
