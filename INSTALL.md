# Install Witness manually and verify

> [!NOTE]
> Please use release v0.7.0 or higher, as prior releases were created to
> test the release workflow.

This repository provides pre-built binaries that are signed and published using
[GoReleaser]. The signature for these binaries are generated using [Sigstore],
using the release workflow's identity. Make sure you have [cosign] installed on
your system, then you will be able to securely download and verify the gittuf
release:

## Unix-like operating systems

```sh
# Modify these values as necessary.
# One of: amd64, arm64
ARCH=amd64
# One of: linux, darwin, freebsd
OS=linux
# See https://github.com/in-toto/witness/releases for the latest version
VERSION=0.7.0
cd $(mktemp -d)

curl -LO https://github.com/in-toto/witness/releases/download/v${VERSION}/witness_${VERSION}_${OS}_${ARCH}
curl -LO https://github.com/in-toto/witness/releases/download/v${VERSION}/witness_${VERSION}_${OS}_${ARCH}.sig
curl -LO https://github.com/in-toto/witness/releases/download/v${VERSION}/witness_${VERSION}_${OS}_${ARCH}.pem

cosign verify-blob \
    --certificate witness_${VERSION}_${OS}_${ARCH}.pem \
    --signature witness_${VERSION}_${OS}_${ARCH}.sig \
    --certificate-identity https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v${VERSION} \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    witness_${VERSION}_${OS}_${ARCH}

sudo install witness_${VERSION}_${OS}_${ARCH} /usr/local/bin/witness
cd -
witness version
```
