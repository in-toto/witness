## witness run

Runs the provided command and records attestations about the execution

```
witness run [cmd] [flags]
```

### Options

```
  -a, --attestations strings                Attestations to record (default [environment,git])
      --certificate string                  Path to the signing key's certificate
      --collector-ca-path string            Path to the collector server's certificate CA data
      --collector-client-cert-path string   Path to the collector client's certificate
      --collector-client-key-path string    Path to the collector client's private key
      --collector-server string             Collector server protocol and address (default "127.0.0.1:8080")
  -h, --help                                help for run
  -i, --intermediates strings               Intermediates that link trust back to a root in the policy
  -k, --key string                          Path to the signing key
  -o, --outfile string                      File to write signed data.  Defaults to stdout
  -r, --rekor-server string                 Rekor server to store attestations
      --spiffe-address string               SPIFFE address for the workload api
      --spiffe-server-id string             Sets allowed SPIFFE ID for dialing the server, defaults to any
      --spiffe-socket string                Path to the SPIFFE Workload API socket
  -s, --step string                         Name of the step being run
      --trace                               enable tracing for the command
  -d, --workingdir string                   Directory that commands will be run from
```

### Options inherited from parent commands

```
  -c, --config string      Path to the witness config file (default ".witness.yaml")
  -l, --log-level string   Level of logging to output (debug, info, warn, error) (default "info")
```

### SEE ALSO

* [witness](witness.md)	 - Collect and verify attestations about your build environments

