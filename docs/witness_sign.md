## witness sign

Signs a file

### Synopsis

Signs a file with the provided key source and outputs the signed file to the specified destination

```
witness sign [file] [flags]
```

### Options

```
  -t, --datatype string                          The URI reference to the type of data being signed. Defaults to the Witness policy type (default "https://witness.testifysec.com/policy/v0.1")
  -h, --help                                     help for sign
  -f, --infile string                            Witness policy file to sign
  -o, --outfile string                           File to write signed data. Defaults to stdout
      --signer-file-cert-path string             Path to the file containing the certificate for the private key
      --signer-file-intermediate-paths strings   Paths to files containing intermediates required to establish trust of the signer's certificate to a root
  -k, --signer-file-key-path string              Path to the file containing the private key
      --signer-fulcio-oidc-client-id string      OIDC client ID to use for authentication
      --signer-fulcio-oidc-issuer string         OIDC issuer to use for authentication
      --signer-fulcio-token string               Raw token to use for authentication
      --signer-fulcio-url string                 Fulcio address to sign with
      --signer-spiffe-socket-path string         Path to the SPIFFE Workload API Socket
      --timestamp-servers strings                Timestamp Authority Servers to use when signing envelope
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

