## witness sign

Signs a file

### Synopsis

Signs a file with the provided key source and outputs the signed file to the specified destination

```
witness sign [file] [flags]
```

### Options

```
      --certificate string             Path to the signing key's certificate
  -t, --datatype string                The URI reference to the type of data being signed. Defaults to the Witness policy type (default "https://witness.testifysec.com/policy/v0.1")
      --fulcio string                  Fulcio address to sign with
      --fulcio-oidc-client-id string   OIDC client ID to use for authentication
      --fulcio-oidc-issuer string      OIDC issuer to use for authentication
  -h, --help                           help for sign
  -f, --infile string                  Witness policy file to sign
  -i, --intermediates strings          Intermediates that link trust back to a root of trust in the policy
  -k, --key string                     Path to the signing key
  -o, --outfile string                 File to write signed data. Defaults to stdout
      --spiffe-socket string           Path to the SPIFFE Workload API socket
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

