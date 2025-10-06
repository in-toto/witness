# KMS Signer
Witness supports signing both attestations (generated with `witness run`) and policies (signed with `witness sign`) using a Key Management Service (KMS) key through the provision of a KMS signer. The KMS signer currently supports AWS KMS and GCP KMS. Follow-up support for Azure Key Vault and HashiCorp Vault (with transit engine) is planned.

## Usage
Based on the KMS signer functionality presented in the [Sigstore Cosign project](https://docs.sigstore.dev/cosign/key_management/overview/), Witness uses a URI-based reference scheme to allow users to declare the KMS signer provider they want to use (e.g., GCP, AWS) and the unique information that identifies the specific key they want to use (e.g., GCP Project, AWS ARN).


### Signing
If a user wanted to use a KMS Key (e.g., GCP KMS) to sign the result of a `witness run` command, they would use a command similar the following:

```yaml
witness run -s test -o test.json --signer-kms-ref=gcpkms://projects/test-project/locations/europe-west2/keyRings/test-keyring/cryptoKeys/test-key -- echo "hello world" > hello.txt
```

Furthermore, if a user wanted to use a KMS Key (e.g., GCP KMS) to sign a policy, they could simply execute a command like:
```yaml
witness sign -f policy.json -o policy-signed.json --signer-kms-ref=gcpkms://projects/test-project/locations/europe-west2/keyRings/test-keyring/cryptoKeys/test-key
```

### Declaring KMS Keys in Witness Policies
A key part of utilizing KMS keys in Witness is being able to declare them in Witness policies so that the attestations they sign can be verified against the policy during `witness verify`. The following is an example of how to declare an AWS KMS key in a Witness policy:
```yaml
{
  "expires": "2035-12-17T23:57:40-05:00",
  "steps": {
    "test": {
      "name": "test",
      "attestations": [
        {
          "type": "https://witness.dev/attestations/command-run/v0.1"
        },
        {
          "type": "https://witness.dev/attestations/product/v0.1"
        },
        {
          "type": "https://witness.dev/attestations/environment/v0.1"
        }
      ],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c"
        }
      ]
    }
  },
  "publickeys": {
    "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c": {
      "keyid": "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c"
    }
  }
}
```

From the above example, there is one functionary declared under the "test" step, which is declared to be of type `publickey` and has a `publickeyid` of `awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c`. This `publickeyid` is then declared in the `publickeys` section of the policy with the same value. You should notice that the `keyid` for this public key is an AWS KMS reference URI. Witness will detect this URI and use it to attempt to verify the attestation using the KMS Signer Provider.

In some situations (e.g., behind an air-gap), the use of a KMS service for verification may not be possible. In this scenario, you can fetch the PEM encoded public key from the KMS service (provided that is supported by the service) and declare it in the `publickeys` section of the policy:
```yaml
{
  "expires": "2035-12-17T23:57:40-05:00",
  "steps": {
    "test": {
      "name": "test",
      "attestations": [
        {
          "type": "https://witness.dev/attestations/command-run/v0.1"
        },
        {
          "type": "https://witness.dev/attestations/product/v0.1"
        },
        {
          "type": "https://witness.dev/attestations/environment/v0.1"
        }
      ],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c"
        }
      ]
    }
  },
  "publickeys": {
    "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c": {
      "keyid": "awskms:///arn:aws:kms:eu-north-1:465819230523:key/742e8ff2-9b9f-6f4b-09a2-50b6dfe2127c",
      "key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE3dU0zRjc0VzBST2U2NXVBcFBSSgpXUjZWSXpCSUhzbGVyVHhhbVB2Q0phcFA1SGI3YU1RcjI5RVFrL0NmNTBGUDByeVZNUnFlN0JjNlF3RWhEem5wClJPVzVLSFpKeXVaanlxNkErTnhvN0o4NDVMeFZuWTZ2K2tpendjZThEVGVwcFBmdUZOM3NzdVJVQWlPQkpuMVEKNTdrcmxZam9rbk1xY2pBYW1OUGpxT1JoQVBlb3BHYVlCT2NZMmhiV05PRXprOUpROEZWL3FiMXlWMFNFd2FCbQowc1pvVEZDT0YvQkZCSkFLc1ZkRlMzclVsRTd0WUVZTllSRnlwTFJYYTA2OTcwQWdFdndyQWU3dE5BN0Z3WnZ2CitnR0NjQS8vNUJHSjFpSGVWUGwyQXRNMFNUWlNXS2JvbmZFM0syUFI3Rm0reFFmTG5CSlc2QS9WVTlYdTUzbngKdXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    }
  }
}
```

In this example, the `key` field is a base64 encoded PEM block of the public key that can be used to verify the attestations. Witness will use this public key to verify the attestations instead of using the KMS service.


### Verifying

The KMS signer can of course be supplied in `witness verify` in order to verify the policy signature that was generated over created policies in `witness sign`:
```yaml
witness verify -p policy-signed.json -a test.json --verifier-kms-ref=gcpkms://projects/test-project/locations/europe-west2/keyRings/test-keyring/cryptoKeys/test-key -f test.txt
```

## Providers
Witness currently supports the following KMS service providers. Please note that this section is a based on the documentation from the [Sigstore Cosign project](https://docs.sigstore.dev/cosign/key_management/overview/).

### AWS
The URI format for AWS KMS is `awskms://$ENDPOINT/$KEYID` where `$ENDPOINT` and `$KEYID` are replaced with the correct values.

The `$ENDPOINT` value is left blank in most scenarios, but can be set for testing with KMS-compatible servers such as [localstack](https://localstack.cloud/).
If omitting a custom endpoint, it is mandatory to prefix the URI with `awskms:///` (with three slashes).

If a custom endpoint is used, you may disable TLS verification by setting the `--signer-kms-aws-insecure-skip-verify` and `--verifier-kms-aws-insecure-skip-verify` flags respectively.

AWS credentials are provided using standard configuration as [described in AWS docs](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials).

If the AWS shared credential and config file locations need to be overridden, the `--signer-kms-aws-credentials-file` and `--signer-kms-aws-config-file` flags can be used.

The following URIs are valid:

- Key ID: `awskms:///1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ID with endpoint: `awskms://localhost:4566/1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ARN: `awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Key ARN with endpoint: `awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Alias name: `awskms:///alias/ExampleAlias`
- Alias name with endpoint: `awskms://localhost:4566/alias/ExampleAlias`
- Alias ARN: `awskms:///arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`
- Alias ARN with endpoint: `awskms://localhost:4566/arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`

### GCP
The URI format for GCP KMS is:

```shell
gcpkms://projects/$PROJECT/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEY/versions/$KEY_VERSION
```

Where `$PROJECT`, `$LOCATION`, `$KEYRING`, `$KEY` and `$KEY_VERSION` are replaced with the correct values.

Witness automatically uses GCP Application Default Credentials for authentication. See the GCP [API documentation](https://cloud.google.com/docs/authentication/production) for information on how to authenticate in different environments.

If you wish to specify a credentials file to be used for authenticating to GCP, you can use the `--signer-kms-gcp-credentials-file` and `--verifier-kms-gcp-credentials-file` flags respectively.

The calling user or service account must have the following IAM roles:

- Safer KMS Viewer Role
- Cloud KMS CryptoKey Signer/Verifier (`roles/cloudkms.signerVerifier`)

### Azure Key Vault
The URI format for Azure Key Vault is:
```shell
azurekms://[VAULT_NAME][VAULT_URI]/[KEY]
```
Where `$VAULT_NAME`, `$VAULT_URI`, and `$KEY` are replaced with the correct values.

The following environment variables must be set to let witness authenticate to Azure Key Vault. (see this [reference](https://devblogs.microsoft.com/azure-sdk/authentication-and-the-azure-sdk/#environment-variables) for more details about Azure SDK Authentication):
- AZURE_TENANT_ID
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET
