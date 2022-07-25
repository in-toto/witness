## witness run

Runs the provided command and records attestations about the execution

```
witness run [cmd] [flags]
```

### Options

```
      --archivist-graph string         Archivist graphql server to retrieve attestations
      --archivist-grpc string          Archivist grpc server to store attestations
  -a, --attestations strings           Attestations to record (default [environment,git])
      --certificate string             Path to the signing key's certificate
      --fulcio string                  Fulcio address to sign with
      --fulcio-oidc-client-id string   OIDC client ID to use for authentication
      --fulcio-oidc-issuer string      OIDC issuer to use for authentication
  -h, --help                           help for run
  -i, --intermediates strings          Intermediates that link trust back to a root of trust in the policy
  -k, --key string                     Path to the signing key
  -o, --outfile string                 File to which to write signed data.  Defaults to stdout
      --spiffe-socket string           Path to the SPIFFE Workload API socket
  -s, --step string                    Name of the step being run
      --trace                          Enable tracing for the command
  -d, --workingdir string              Directory from which commands will run
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

