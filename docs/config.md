## Witness Configuration

TestifySec Witness looks for the configuration file `.witness.yaml` in the current directory.

Any values in the configuration file will be overridden by the command line arguments.

<!-- Config file YAML placeholder -->
```yaml
run:
    archivist-server: ""
    archivista-server: ""
    attestations: []
    attestor-product-exclude-glob: ""
    attestor-product-include-glob: ""
    enable-archivist: ""
    enable-archivista: ""
    hashes: []
    outfile: ""
    signer-file-cert-path: ""
    signer-file-intermediate-paths: []
    signer-file-key-path: ""
    signer-fulcio-oidc-client-id: ""
    signer-fulcio-oidc-issuer: ""
    signer-fulcio-token: ""
    signer-fulcio-token-path: ""
    signer-fulcio-url: ""
    signer-spiffe-socket-path: ""
    signer-vault-altnames: []
    signer-vault-commonname: ""
    signer-vault-namespace: ""
    signer-vault-pki-secrets-engine-path: ""
    signer-vault-role: ""
    signer-vault-token: ""
    signer-vault-ttl: ""
    signer-vault-url: ""
    step: ""
    timestamp-servers: []
    trace: ""
    workingdir: ""
sign:
    datatype: ""
    infile: ""
    outfile: ""
    signer-file-cert-path: ""
    signer-file-intermediate-paths: []
    signer-file-key-path: ""
    signer-fulcio-oidc-client-id: ""
    signer-fulcio-oidc-issuer: ""
    signer-fulcio-token: ""
    signer-fulcio-token-path: ""
    signer-fulcio-url: ""
    signer-spiffe-socket-path: ""
    signer-vault-altnames: []
    signer-vault-commonname: ""
    signer-vault-namespace: ""
    signer-vault-pki-secrets-engine-path: ""
    signer-vault-role: ""
    signer-vault-token: ""
    signer-vault-ttl: ""
    signer-vault-url: ""
    timestamp-servers: []
verify:
    archivist-server: ""
    archivista-server: ""
    artifactfile: ""
    attestations: []
    enable-archivist: ""
    enable-archivista: ""
    policy: ""
    policy-ca: []
    publickey: ""
    subjects: []

```
