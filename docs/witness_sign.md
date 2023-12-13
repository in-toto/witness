## witness sign

Signs a file

### Synopsis

Signs a file with the provided key source and outputs the signed file to the specified destination

```
witness sign [file] [flags]
```

### Options

```
  -t, --datatype string                               The URI reference to the type of data being signed. Defaults to the Witness policy type (default "https://witness.testifysec.com/policy/v0.1")
  -h, --help                                          help for sign
  -f, --infile string                                 Witness policy file to sign
  -o, --outfile string                                File to write signed data. Defaults to stdout
      --signer-file-cert-path string                  Path to the file containing the certificate for the private key
      --signer-file-intermediate-paths strings        Paths to files containing intermediates required to establish trust of the signer's certificate to a root
  -k, --signer-file-key-path string                   Path to the file containing the private key
      --signer-fulcio-oidc-client-id string           OIDC client ID to use for authentication
      --signer-fulcio-oidc-issuer string              OIDC issuer to use for authentication
      --signer-fulcio-token string                    Raw token to use for authentication
      --signer-fulcio-url string                      Fulcio address to sign with
      --signer-spiffe-socket-path string              Path to the SPIFFE Workload API Socket
      --signer-vault-altnames strings                 Alt names to use for the generated certificate. All alt names must be allowed by the vault role policy
      --signer-vault-commonname string                Common name to use for the generated certificate. Must be allowed by the vault role policy
      --signer-vault-namespace string                 Vault namespace to use
      --signer-vault-pki-secrets-engine-path string   Path to the Vault PKI Secrets Engine to use (default "pki")
      --signer-vault-role string                      Name of the Vault role to generate the certificate for
      --signer-vault-token string                     Token to use to connect to Vault
      --signer-vault-ttl duration                     Time to live for the generated certificate. Defaults to the vault role policy's configured TTL if not provided
      --signer-vault-url string                       Base url of the Vault instance to connect to
      --timestamp-servers strings                     Timestamp Authority Servers to use when signing envelope
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments


## Using [SPIRE](https://github.com/spiffe/spire) for Keyless Signing

Witness can consume ephemeral keys from a [SPIRE](https://github.com/spiffe/spire) node agent. Configure witness with the flag `--spiffe-socket` to enable keyless signing.

During the verification process witness will use a source of trusted time such as a timestamp from a timestamp authority to make a determination on certificate validity. The SPIRE certificate only needs to remain valid long enough for a timestamp to be created.

