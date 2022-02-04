# OCI Attestor

The OCI attestor records information about a provided OCI image stored on disk as a tarball.
Information about the image's tags, layers, and manifest are collected and reported in this
attestation.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `tardigest` | Digest of the tarred image |
| `imageid` | ID of the image |
| `layerdiffid` | Layer diff IDs of the image |
