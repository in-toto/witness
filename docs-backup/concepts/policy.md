
# Policies
## What is a witness policy?
A witness policy is a signed document that encodes the requirements for an artifact to be validated. A witness policy includes public keys for trusted functionaries, which attestations must be found, and rego policy to evaluate against the attestation meta-data. This allows users to make assertions and test attestation collections generated during a `witness run`, allowing administrators to trace the compliance status of an artifact at any point during its lifecycle.

Policies help you ensure that all expected attestations are within a collection and support embedded
[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies to make determinations about the content
of each attestation. Attestation signatures can be linked to trusted functionaries with embedded public keys or [X.509](https://en.wikipedia.org/wiki/X.509)
roots of trust.

Combining these powers, Witness policies ultimately allow users to make decisions automatically about the
trustworthiness of an artifact. Details of who, how, when, and where an artifact was built can all be considered
when evaluating policies.

## Verification Process

`Witness verify` will evaluate a set of attestation collections against a policy document. If the attestation
collections satisfy the policy, Witness will exit with an exit code of 0. Any other exit code indicates an error or
policy failure.

Evaluating a Witness policy involves a few different steps:

1. Verify signatures on collections against public keys and trust roots within the policy. Any collections that fail signature
   verification will not be used.
2. Verify the signer of each collection maps to a trusted functionary for the corresponding step in the policy.
3. Verify that a signature is optionally timestamped by a trusted timestamp authority defined by the policy.
4. Verify that materials recorded in each collection are consistent with the artifacts (materials + products) of other
   collections as configured by the policy.
5. Verify all rego policies embedded in the policy evaluate successfully against collections.

## Use Cases
Examples of when a policy could be verified include:
- within a [Kubernetes admission controller](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- at the end of a CI/CD pipeline
- prior to image promotion, or
- before deployment to an execution environment.

## Schema

Policies are JSON documents that are signed and wrapped in [DSSE envelopes](https://github.com/secure-systems-lab/dsse). The DSSE payload type will be
`https://witness.testifysec.com/policy/v0.1`.

### `policy` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `expires` | string | [ISO-8601](https://en.wikipedia.org/wiki/ISO_8601) formatted time. This key defines an expiration time for the policy. Evaluation of expired policies always fails. |
| `roots` | object | Trusted [X.509 root certificates](https://en.wikipedia.org/wiki/X.509). Attestations that are signed with a certificate that belong to this root will be trusted. Keys of the object are the root certificate's Key ID, values are a `root` object. |
| `publickeys` | object | Trusted public keys. Attestations that are signed with one of these keys will be trusted. Keys of the object are the public key's Key ID, values are a `publickey` object. |
| `steps` | object | Expected steps that must appear to satisfy the policy. Each step requires an attestation collection with a matching name and the expected attestations. Keys of the object are the step's name, values are a `step` object. |
| `timestampauthorities` | object | Trusted [X.509 root certificates](https://en.wikipedia.org/wiki/X.509). Signatures that include a timestamp from a timestamp authority must belong to a timestamp authority root defined in this object. Keys of the object are the root certificate's Key ID, values are a `root` object. |

### `root` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `certificate` | string | [Base64](https://en.wikipedia.org/wiki/Base64) encoded [PEM](https://pkg.go.dev/encoding/pem) block that describes a valid X.509 root certificate. |
| `intermediates` | array of strings | Array of base64 encoded PEM blocks that describe valid X.509 intermediate certificates belonging to `certificate` |

### `publickey` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `keyid` | string | [sha256sum](https://linux.die.net/man/1/sha256sum) of the public key |
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
| `certConstraint` | `certConstraint` object | Object defining constraints upon the signer's certificate for "root" functionaries. Only valid if `type` is "root". |
| `publickeyid` | string | Key ID of a public key that is trusted to sign this step. Only valid if `type` is "publickey". |

### `certConstraint` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `commonname` | string | Common name that the certifiate's subject must have |
| `dnsnames` | array of strings | DNS names that the certificate must have |
| `emails` | array of strings | Email addresses that the certificate must have |
| `organizations` | array of strings | Organizations that the certificate must have |
| `uris` | array of strings | URIs that the certificate must have |
| `roots` | array of strings | Array of Key IDs the signer's certificate must belong to be trusted. |

Every attribute of the certificate must match the attributes defined by the constraint exactly. A certificate must match
at least one constraint to pass the policy. Wildcards are allowed if they are the only element in the constraint.

Example of a constraint that would allow use of any certificate, as long as it belongs to a root defined in the policy:

```
{
  "commonname": "*",
  "dnsnames": ["*"],
  "emails": ["*"],
  "organizations": ["*"],
  "uris": ["*"],
  "roots": ["*"]
}
```

[SPIFFE](https://spiffe.io/) IDs are defined as URIs on the certificate, so a policy that would enforce a SPIFFE ID may look like:

```
{
  "commonname": "*",
  "dnsnames": ["*"],
  "emails": ["*"],
  "organizations": ["*"],
  "uris": ["spiffe://example.com/step1"],
  "roots": ["*"]
}
```

### `attestation` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `type` | string | Type reference of an attestation that must appear in a step. |
| `regopolicies` | array of `regopolicy` objects | [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies that will be run against the attestation. All must pass. |

### `regopolicy` Object

| Key | Type | Description |
| --- | ---- | ----------- |
| `name` | string | Name of the rego policy. Will be reported on failures. |
| `module` | string | Base64 encoded rego module |

Rego modules are expected to output a data with the name of `deny` in the case of a rego policy evaluation failure.
`deny` can be a string or an array of strings and should be populated with a human-readable string describing why the
policy was denied. Any other data output by the module will be ignored.

Following is an example output for a valid rego policy:

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
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": []
        },
        {
          "type": "https://witness.dev/attestations/command-run/v0.1",
          "regopolicies": [
            {
              "name": "expected command",
              "module": "cGFja2FnZSBjb21tYW5kcnVuLmNtZAoKZGVueVttc2ddIHsKCWlucHV0LmNtZCAhPSBbImdvIiwgImJ1aWxkIiwgIi1vPXRlc3RhcHAiLCAiLiJdCgltc2cgOj0gInVuZXhwZWN0ZWQgY21kIgp9Cg=="
            }
          ]
        },
        {
          "type": "https://witness.dev/attestations/product/v0.1",
          "regopolicies": []
        }
      ],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647"
        },
        {
          "type": "root",
          "certConstraint": {
            "commonname": "*",
            "dnsnames": ["*"],
            "emails": ["*"],
            "organizations": ["*"],
            "uris": ["spiffe://example.com/step1"],
            "roots": ["ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647"]
          }
        }
      ]
    }
  },
  "publickeys": {
    "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647": {
      "keyid": "ae2dcc989ea9c109a36e8eba5c4bc16d8fafcfe8e1a614164670d50aedacd647",
      "key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQWYyOW9QUDhVZ2hCeUc4NTJ1QmRPeHJKS0tuN01NNWhUYlA5ZXNnT1ovazA9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
    }
  },
  "roots": {
    "949aaab542a02514f27f41ed8e443bb54bbd9b062ca3ce1da2492170d8fffe98": {
      "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURhekNDQWxPZ0F3SUJBZ0lVSnlobzI5ckorTXZYdGhGZjRncnV3UWhUZVNNd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1JURUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJRmRwWkdkcGRITWdVSFI1SUV4MFpEQWVGdzB5TWpBeU1qTXlNalV4TkRoYUZ3MHlOekF5Ck1qSXlNalV4TkRoYU1FVXhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1TRXcKSHdZRFZRUUtEQmhKYm5SbGNtNWxkQ0JYYVdSbmFYUnpJRkIwZVNCTWRHUXdnZ0VpTUEwR0NTcUdTSWIzRFFFQgpBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ3VnVnNVYlV1cHB6S3ArOUxyckxLeGFrc0JlVTRiei9lQ0w1ZXo0bEppClFhcm1vcVRDeWI0WlVqVTNTSCsxYVdLSU9aM2kyeUZmL0hYRktNemh5SHFWZnpzbDVJUEo5TzVTR0huK3FldnoKVzBTMVdQeEN4MS9KdlFoUFNaQ21adWhaMmI5NFVYdXhCL2tSWGRiNnhYdnVReVFPMDYybTQrTkZWYVhBWWZjTQprVUlBSnpQTUZUSHhKOUQ1dWdaMWlSV0VHUUQ1d2kwNS9ZRG5yZHR3N2J3V3ZkOW4yL3c1UHUvUU1iVHZ4NWxlCnNFK2U1ZWZZd1NZLzBvT2dWRHBHVG9TVStpeDMrYWVlVjFSL1IvNm81NlJ0LzQ5eG9KWjF5bCtyQ3ByOUswN3AKL0FOSk9HTE5oYlRXVGp1N1lTSUxtbnYreVJwRUdUTnptU1lpNEFFTStZYm5BZ01CQUFHalV6QlJNQjBHQTFVZApEZ1FXQkJRemppS2pzR1NZNjUvNTFlQVJINVpEdXFIOUtEQWZCZ05WSFNNRUdEQVdnQlF6amlLanNHU1k2NS81CjFlQVJINVpEdXFIOUtEQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQmgKUXhBNWExMUJ4VXh6Q1hObDg4ZUxkaDg5NlNudkdwYkNTZVhxQzJKS0w2QkxHVHg4NC9SZmMxNzVyZ2VUTW9YcQpEWjA1Nm9xc1FPZ2czWVRXWEJDMTJJbmVnUW40Wm90L2cydWk3cTJOZ0NZNWNSSG9qZnhQd2JxbS9uU2k1eXNSClFCQTZuMUJ3cUlZclBpVVBvcE9YY1BIQVJ4SEwzUitIOHRpWCtyM1hRM3FZdnNuTUpOL3JlcGJOQjJKVi9TL28KT0llT1U5Y1RJRnRHNWNNd2RHcTdMeVlkK095NkRiNjN5aDNkNS82bEZOVElqdlZXaHhzS280U3dxZlhuOXY4TApia2xTOFB0Mm12MVMxa2thZGhMT1FqaGlBQ1N2UHB6OW5USXdXWTJUYTcvNGpFR0I3ZTF3aU8wZ0dhbFJhVXQyClpmYmt3eXFSQWxXUXNBcDJqZS8wCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    }
  },
  "timestampauthorities": {
    "freetsa": {
      "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUgvekNDQmVlZ0F3SUJBZ0lKQU1IcGhoWU5xT21BTUEwR0NTcUdTSWIzRFFFQkRRVUFNSUdWTVJFd0R3WUQKVlFRS0V3aEdjbVZsSUZSVFFURVFNQTRHQTFVRUN4TUhVbTl2ZENCRFFURVlNQllHQTFVRUF4TVBkM2QzTG1aeQpaV1YwYzJFdWIzSm5NU0l3SUFZSktvWklodmNOQVFrQkZoTmlkWE5wYkdWNllYTkFaMjFoYVd3dVkyOXRNUkl3CkVBWURWUVFIRXdsWGRXVnllbUoxY21jeER6QU5CZ05WQkFnVEJrSmhlV1Z5YmpFTE1Ba0dBMVVFQmhNQ1JFVXcKSGhjTk1UWXdNekV6TURFMU1qRXpXaGNOTkRFd016QTNNREUxTWpFeldqQ0JsVEVSTUE4R0ExVUVDaE1JUm5KbApaU0JVVTBFeEVEQU9CZ05WQkFzVEIxSnZiM1FnUTBFeEdEQVdCZ05WQkFNVEQzZDNkeTVtY21WbGRITmhMbTl5Clp6RWlNQ0FHQ1NxR1NJYjNEUUVKQVJZVFluVnphV3hsZW1GelFHZHRZV2xzTG1OdmJURVNNQkFHQTFVRUJ4TUoKVjNWbGNucGlkWEpuTVE4d0RRWURWUVFJRXdaQ1lYbGxjbTR4Q3pBSkJnTlZCQVlUQWtSRk1JSUNJakFOQmdrcQpoa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXRnS09EakF5OFJFUTJXVE5xVXVkQW5qaGxDcnBFNnFsCm1RZk5wcGVUbVZ2WnJINHp1dG4rTndUYUhBR3BqU0d2NC9XUnBaMXdaM0JSWjVtUFVCWnlMZ3EwWXJJZlE1RngKMHMvTVJaUHpjMXIzbEtXck1SOXNBUXg0bU40ejExeEZFTzUyOUwwZEZKalBGOU1EOEdwZDJmZVd6R3lwdGxlbApiK1BxVCsrK2ZPYTJvWTArTmFNTTdsL3hjTkhQT2FNejAvMm9sazBpMjJoYktlVmh2b2tQQ3FoRmh6c3VoS3NtCnE0T2Yvbyt0NmRJN3N4NWgwblBNbTRnR1NSaGZxK3o2QlRSZ0NycVFHMkZPTG9WRmd0NmlJbS9Cbk5mZlVyN1YKRFlkM3pabUl3Rk9qL0gzREtIb0dpay94SzNFODJZQTJadWxWT0ZSVy96ajRBcGpQYTVPRmJwSWtkMHBtenh6ZApFY0w0NzloU0E5ZEZpeVZtU3hQdFk1emUxUCtCRTliTVUxUFNjcFJ6dzhNSEZYeHlLcVcxM1F2N0xXdzRzYmszClNjaUI3R0FDYlFpVkd6Z2t2WEc2eTg1SE91dldOdkM1R0xTaXlQOUdsUEIwVjY4dGJ4ejRKVlRSZHcvWG4vWFQKRk56UkJNM2NxOGxCT0FWdC9QQVg1K3VGY3YxUzl3RkU4WWphQmZXQ1AxamRCaWwrYzRlKzB0ZHl3VDJvSm1ZQgpCRi9rRXQxd21Hd01tSHVuTkV1UU56aDFGdEpZNTRoYlVmaVdpMzhtQVNFN3hNdE1oZmovQzRTdmFwaUROODM3CmdZYVBmczh4M0taeGJYN0MzWUFzRm5KaW5sd0FVc3MxZmRLYXI4US9ZVnM3SC9uVTRjNEl4eHh6NGY2N2ZjVnEKTTJJVEtlbnRiQ01DQXdFQUFhT0NBazR3Z2dKS01Bd0dBMVVkRXdRRk1BTUJBZjh3RGdZRFZSMFBBUUgvQkFRRApBZ0hHTUIwR0ExVWREZ1FXQkJUNlZRMk1OR1pSUTB6MzU3T25iSld2ZXVha2x6Q0J5Z1lEVlIwakJJSENNSUcvCmdCVDZWUTJNTkdaUlEwejM1N09uYkpXdmV1YWtsNkdCbTZTQm1EQ0JsVEVSTUE4R0ExVUVDaE1JUm5KbFpTQlUKVTBFeEVEQU9CZ05WQkFzVEIxSnZiM1FnUTBFeEdEQVdCZ05WQkFNVEQzZDNkeTVtY21WbGRITmhMbTl5WnpFaQpNQ0FHQ1NxR1NJYjNEUUVKQVJZVFluVnphV3hsZW1GelFHZHRZV2xzTG1OdmJURVNNQkFHQTFVRUJ4TUpWM1ZsCmNucGlkWEpuTVE4d0RRWURWUVFJRXdaQ1lYbGxjbTR4Q3pBSkJnTlZCQVlUQWtSRmdna0F3ZW1HRmcybzZZQXcKTXdZRFZSMGZCQ3d3S2pBb29DYWdKSVlpYUhSMGNEb3ZMM2QzZHk1bWNtVmxkSE5oTG05eVp5OXliMjkwWDJOaApMbU55YkRDQnp3WURWUjBnQklISE1JSEVNSUhCQmdvckJnRUVBWUh5SkFFQk1JR3lNRE1HQ0NzR0FRVUZCd0lCCkZpZG9kSFJ3T2k4dmQzZDNMbVp5WldWMGMyRXViM0puTDJaeVpXVjBjMkZmWTNCekxtaDBiV3d3TWdZSUt3WUIKQlFVSEFnRVdKbWgwZEhBNkx5OTNkM2N1Wm5KbFpYUnpZUzV2Y21jdlpuSmxaWFJ6WVY5amNITXVjR1JtTUVjRwpDQ3NHQVFVRkJ3SUNNRHNhT1VaeVpXVlVVMEVnZEhKMWMzUmxaQ0IwYVcxbGMzUmhiWEJwYm1jZ1UyOW1kSGRoCmNtVWdZWE1nWVNCVFpYSjJhV05sSUNoVFlXRlRLVEEzQmdnckJnRUZCUWNCQVFRck1Da3dKd1lJS3dZQkJRVUgKTUFHR0cyaDBkSEE2THk5M2QzY3VabkpsWlhSellTNXZjbWM2TWpVMk1EQU5CZ2txaGtpRzl3MEJBUTBGQUFPQwpBZ0VBYUs5K3Y1T0ZZdTlNNnp0WUMrTDY5c3cxb21keWxpODlsWkFmcFdNTWg5Q1JtSmhNNktCcU0vaXB3b0x0Cm54eXhHc2JDUGhjUWp1VHZ6bSt5bE42VndUTW1JbFZ5VlNMS1laY2RTanQvZUNVTis0MUs3c0Q3R1ZteFpCQUYKSUxuQkRtVEdKbUxrclUwS3V1SXBqOGxJL0U2WjZObm11UDIrUkFRU0hzZkJRaTZzc3NuWE1vNEhPVzVndFBPNwpnRHJVcFZYSUQrKzFQNFhuZGtvS243U3Z3NW4welM5ZnYxaHhCY1lJSFBQUVV6ZTJ1MzBiQVF0MG4waUl5Ukx6CmFXdWh0cEF0ZDdmZndFYkFTZ3pCN0UrTkdGNHRwVjM3ZThLaUEyeGlHU1JxVDVuZHUyOGZncE9ZODdnRDNBcloKRGN0WnZ2VENmSGRBUzVrRU8zZ25HR2VaRVZMRG1mRXN2OFRHSmEzQWxqVmE1RTQwSVFEc1VYcFFMaThHK1VDNAoxRFdadThFVlQ0cm5ZYUN3MVZYN1NoT1IxUE5DQ3ZqYjhTOHRmZHVkZDl6aFUzZ0VCMHJ4ZGVUeTF0VmJOTFhXCjk5eTkweGN3cjFaSURVd00veFEvbm9POEZSaG0wTG9QQzczRWYrSjRaQmRydld3YXVGM3pKZTMzZDRpYnhFY2IKOC9wejVXekZrZWl4WU0ybnNIaHFIc0JLdzdKUG91S05YUm5sNUlBRTFlRm1xRHlDN0cvVlQ3T0Y2Njl4TTZoYgpVdDVHMjFKRTRjTks2Tk51Y1MrZnpnMUpQWDArM1Zoc1laamo3RDV1bGpSdlFYcko4aUhnci9NNmoyb0xIdlRBCkkyTUxkcTJxalpGRE9DWHN4QnhKcGJtTEdCeDlvdzZaZXJsVXh6d3MyQVd2MnBrPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
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

The above example policy requires that two attestation collections be present, one named "clone" and one named "build". Both
collections must have a material, command-run, and product attestor within them. The command-run attestor for the
"build" collection must have recorded a command of `go build -o=testapp .` to pass the embedded rego policy. The build
step is configured to ensure the materials used are consistent with the artifacts from the clone step, assuring that
files used during the build process are the same that were produced during the clone step.
