## witness verify

Verifies a witness policy

### Synopsis

Verifies a policy provided key source and exits with code 0 if verification succeeds

```
witness verify [flags]
```

### Options

```
      --archivista-server string   URL of the Archivista server to store or retrieve attestations (default "https://archivista.testifysec.io")
  -f, --artifactfile string        Path to the artifact to verify
  -a, --attestations strings       Attestation files to test against the policy
      --enable-archivista          Use Archivista to store or retrieve attestations
  -h, --help                       help for verify
  -p, --policy string              Path to the policy to verify
      --policy-ca strings          Paths to CA certificates to use for verifying the policy
  -k, --publickey string           Path to the policy signer's public key
  -s, --subjects strings           Additional subjects to lookup attestations
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments
