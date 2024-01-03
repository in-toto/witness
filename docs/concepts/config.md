# Witness Configuration

Witness allows the user to specify a `yaml` file for persisting the command line flags to be set whenever Witness is invoked. Any values in the configuration file will be overridden by the command line flags set on command invocation.

By default, Witness will look for the configuration file in the `.witness.yaml` path in the directory from wihch Witness is invoked.  The user can specify a different path using the `--config` flag.

The schema of the configuration file mirrors the names of the command line flags. For example, the `--attestations` flag for the `run` command is set in the configuration file as `run.attestations`.  The `--spiffe-socket` flag for the `sign` command is set in the configuration file as `sign.spiffe-socket`. The full schema is listed below:
```yaml
run:
    attestations: stringSlice
    certificate: string
    intermediates: stringSlice
    key: string
    outfile: string
    rekor-server: string
    spiffe-socket: string
    step: string
    trace: bool
    workingdir: string
sign:
    certificate: string
    datatype: string
    intermediates: stringSlice
    key: string
    outfile: string
    spiffe-socket: string
verify:
    artifactfile: string
    artifacthash: string
    attestations: stringSlice
    publickey: string
    policy: string
```
