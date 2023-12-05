## witness run

Runs the provided command and records attestations about the execution

```
witness run [cmd] [flags]
```

### Options

```
      --archivista-server string                      URL of the Archivista server to store or retrieve attestations (default "https://archivista.testifysec.io")
  -a, --attestations strings                          Attestations to record (default [environment,git])
      --attestor-product-exclude-glob string          Pattern to use when recording products. Files that match this pattern will be excluded as subjects on the attestation.
      --attestor-product-include-glob string          Pattern to use when recording products. Files that match this pattern will be included as subjects on the attestation. (default "*")
      --enable-archivista                             Use Archivista to store or retrieve attestations
      --hashes strings                                Hashes selected for digest calculation. Defaults to SHA256 (default [sha256])
  -h, --help                                          help for run
  -o, --outfile string                                File to which to write signed data.  Defaults to stdout
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
  -s, --step string                                   Name of the step being run
      --timestamp-servers strings                     Timestamp Authority Servers to use when signing envelope
      --trace                                         Enable tracing for the command
  -d, --workingdir string                             Directory from which commands will run
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments
