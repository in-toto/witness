## witness verify

Verifies a witness policy

### Synopsis

Verifies a policy provided key source and exits with code 0 if verification succeeds

```
witness verify [flags]
```

### Options

```
  -f, --artifactfile string    Path to the artifact to verify
      --artifacthash string    Hash of the artifact to verify
  -a, --attestations strings   Attestation files to test against the policy
  -h, --help                   help for verify
  -p, --policy string          Path to the policy to verify
  -k, --publickey string       Path to the policy signer's public key
```

### Options inherited from parent commands

```
  -c, --config string   Path to the witness config file (default ".witness.yaml")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

