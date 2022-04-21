## Witness Configuration

TestifySec Witness looks for the configuration file `.witness.yaml` in the current directory.

Any values in the configuration file will be overridden by the command line arguments.

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
