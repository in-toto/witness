# witness-cli

## witness

Collect and verify attestations about your build environments

### Options

```
  -h, --help   help for witness
```

## run

Runs the provided command and records attestations about the execution

```
run [cmd] [flags]
```

### Options

```
  -h, --help   help for run
```

## witness sign

Signs a file

### Synopsis

Signs a file with the provided key source and outputs the signed file to the specified destination

```
witness sign [file] [flags]
```

### Options

```
  -c, --certificate string      Path to the signing key's certificate
  -t, --datatype string         The URI reference to the type of data being signed. Defaults to the Witness policy type (default "https://witness.testifysec.com/policy/v0.1")
  -h, --help                    help for sign
  -i, --intermediates strings   Intermediates that link trust back to a root in the policy
  -k, --key string              Path to the signing key
  -o, --outfile string          File to write signed data. Defaults to stdout
      --spiffe-socket string    Path to the SPIFFE Workload API socket
```

## witness verify

Verifies a witness layout

### Synopsis

Verifies a layout provided key source and exits with code 0 if verification succeeds

```
witness verify [flags]
```

### Options

```
  -f, --artifactfile string    Path to the artifact to verify
      --artifacthash string    Hash of the artifact to verify
  -a, --attestations strings   Attestation files to test against the policy
  -h, --help                   help for verify
  -k, --layout-key string      Path to the layout signer's public key
  -p, --policy string          Path to the policy to verify
```

