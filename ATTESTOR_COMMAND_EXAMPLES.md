# Witness Attestor Command Examples

This guide provides realistic command examples for each attestor, showing the proper syntax and common use cases.

## Basic Command Structure

```bash
witness run -s <step-name> -k <key-path> [-a <attestor>] [-o <output-file>] -- <command>
```

- `-s`: Step name (required)
- `-k`: Path to signing key (required)
- `-a`: Attestor(s) to use (optional, defaults to environment,git)
- `-o`: Output file for attestation (optional)
- `--`: Separator before the actual command to run

## Attestor Examples

### Git Attestor
Captures repository state including commit, branch, and working directory status.

```bash
# Basic usage
witness run -s build -k key.pem -a git -- go build ./...

# With multiple attestors
witness run -s build -k key.pem -a git,environment -- make build

# Save attestation to file
witness run -s build -k key.pem -a git -o git-attestation.json -- npm run build
```

### Environment Attestor
Records environment variables and system information.

```bash
# Capture environment during tests
witness run -s test -k key.pem -a environment -- pytest

# Filter sensitive variables
witness run -s build -k key.pem -a environment --env-filter-sensitive-vars -- make deploy

# Add custom sensitive keys
witness run -s build -k key.pem -a environment --env-add-sensitive-key 'API_*' -- ./build.sh
```

### Material Attestor
Records cryptographic hashes of input files before command execution.

```bash
# Rust build with input tracking
witness run -s build -k key.pem -a material -- cargo build --release

# Go build tracking source files
witness run -s compile -k key.pem -a material,product -- go build -o myapp ./cmd/main.go
```

### Product Attestor
Records cryptographic hashes of files created or modified during execution.

```bash
# Track build outputs
witness run -s package -k key.pem -a product -- npm run build

# With specific output patterns
witness run -s build -k key.pem -a product --attestor-product-include-glob='dist/**' -- webpack
```

### Command Run Attestor
Automatically included - records command execution details.

```bash
# Command run is automatic, no -a flag needed
witness run -s compile -k key.pem -- make build

# With tracing enabled (Linux only)
witness run -s build -k key.pem --trace -- ./build.sh
```

### Docker Attestor
Captures Docker image metadata during builds.

```bash
# Docker build
witness run -s package -k key.pem -a docker -- docker build -t myapp:latest .

# Docker buildx with multi-arch
witness run -s build -k key.pem -a docker -- docker buildx build --platform linux/amd64,linux/arm64 -t myapp:latest .
```

### AWS Attestor (EC2 only)
Captures AWS EC2 instance identity.

```bash
# Terraform deployment on EC2
witness run -s deploy -k key.pem -a aws -- terraform apply

# AWS SAM deployment
witness run -s deploy -k key.pem -a aws,environment -- sam deploy --guided
```

### GCP IIT Attestor (GCP only)
Captures Google Cloud instance identity.

```bash
# GCP deployment
witness run -s deploy -k key.pem -a gcp-iit -- gcloud app deploy

# Cloud Run deployment
witness run -s deploy -k key.pem -a gcp-iit -- gcloud run deploy myservice --image gcr.io/project/image
```

### GitHub Actions Attestor
Captures GitHub Actions workflow context.

```bash
# In GitHub Actions workflow
witness run -s build -k key.pem -a github -- npm test

# With artifact upload
witness run -s release -k key.pem -a github,product -- goreleaser release --clean
```

### GitLab CI Attestor
Captures GitLab CI pipeline context.

```bash
# In GitLab CI pipeline
witness run -s test -k key.pem -a gitlab -- gradle test

# With Docker build
witness run -s build -k key.pem -a gitlab,docker -- docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
```

### Jenkins Attestor
Captures Jenkins build environment.

```bash
# Maven build in Jenkins
witness run -s build -k key.pem -a jenkins -- mvn clean package

# Gradle build
witness run -s build -k key.pem -a jenkins -- ./gradlew build
```

### JWT Attestor
Verifies and records JWT tokens.

```bash
# Kubernetes deployment with workload identity
witness run -s deploy -k key.pem -a jwt -- kubectl apply -f deployment.yaml

# With custom JWKS URL
witness run -s deploy -k key.pem -a jwt --jwt-jwks-url https://issuer.example.com/.well-known/jwks.json -- helm upgrade myapp ./chart
```

### Link Attestor
Creates in-toto compatible attestations.

```bash
# Create named link attestation
witness run -s release -k key.pem -a link --attestor-link-name=build -- make release

# Export link attestation
witness run -s build -k key.pem -a link --attestor-link-export -- cargo build --release
```

### SBOM Attestor
Records Software Bill of Materials.

```bash
# Generate and attest SBOM
syft . -o spdx-json > sbom.json
witness run -s scan -k key.pem -a sbom -- echo "SBOM generated"

# With CycloneDX format
cyclonedx-cli app -o sbom.json
witness run -s scan -k key.pem -a sbom -- echo "SBOM generated"
```

### SLSA Attestor
Generates SLSA provenance.

```bash
# Generate SLSA provenance
witness run -s release -k key.pem -a slsa -- goreleaser release

# Export provenance separately
witness run -s build -k key.pem -a slsa --attestor-slsa-export=provenance.json -- make dist
```

### Secret Scan Attestor
Scans for secrets in code and attestations.

```bash
# Scan during tests
witness run -s test -k key.pem -a secretscan -- go test ./...

# Fail on detection
witness run -s scan -k key.pem -a secretscan --attestor-secretscan-fail-on-detection -- npm test
```

### OCI Attestor
Records OCI registry operations.

```bash
# Push to registry
witness run -s push -k key.pem -a oci -- crane push image.tar registry.io/myapp:latest

# With cosign
witness run -s sign -k key.pem -a oci -- cosign sign registry.io/myapp:latest
```

### Kubernetes Manifest Attestor
Records Kubernetes manifests.

```bash
# Deploy to Kubernetes
witness run -s deploy -k key.pem -a k8smanifest -- kubectl apply -f manifests/

# With dry-run
witness run -s deploy -k key.pem -a k8smanifest --attestor-k8smanifest-server-side-dry-run -- kubectl apply -f deployment.yaml
```

### VEX Attestor
Records vulnerability assessments.

```bash
# Create VEX document
witness run -s assess -k key.pem -a vex -- vexctl create --product pkg:oci/myimage@sha256:abc...

# With OpenVEX
witness run -s assess -k key.pem -a vex -- openvex create --product myapp --vuln CVE-2023-1234
```

### System Packages Attestor
Records installed system packages.

```bash
# Before system setup
witness run -s setup -k key.pem -a system-packages -- apt-get update && apt-get install -y build-essential

# RPM-based systems
witness run -s setup -k key.pem -a system-packages -- yum install -y gcc make
```

### Lockfiles Attestor
Captures dependency lockfiles.

```bash
# Node.js install
witness run -s install -k key.pem -a lockfiles -- npm ci

# Python install
witness run -s install -k key.pem -a lockfiles -- pip install -r requirements.txt

# Go modules
witness run -s install -k key.pem -a lockfiles -- go mod download
```

### Maven Attestor
Records Maven build information.

```bash
# Maven build
witness run -s build -k key.pem -a maven -- mvn clean install

# With custom POM
witness run -s build -k key.pem -a maven --attestor-maven-pom-path=parent/pom.xml -- mvn package
```

### SARIF Attestor
Captures security scan results.

```bash
# Semgrep scan
semgrep --config=auto --sarif -o results.sarif .
witness run -s scan -k key.pem -a sarif -- echo "Scan complete"

# CodeQL scan
codeql database analyze --format=sarif-latest -o results.sarif db
witness run -s scan -k key.pem -a sarif -- echo "Analysis complete"
```

### OmniTrail Attestor
Creates OmniTrail envelopes.

```bash
# Full build tracking
witness run -s build -k key.pem -a omnitrail -- make all

# With specific targets
witness run -s build -k key.pem -a omnitrail,material,product -- ./build.sh --release
```

### Policy Verify Attestor
Used with witness verify command.

```bash
# Verify with policy
witness verify -p policy.json -k policy-key.pem -a policyverify --subjects build.tar.gz

# With Archivista
witness verify -p policy.json -k policy-key.pem -a policyverify --enable-archivista --subjects myapp:latest
```

## Common Patterns

### Multiple Attestors
```bash
# Comprehensive build attestation
witness run -s build -k key.pem \
  -a git,environment,material,product,sbom,slsa \
  -o build-attestation.json \
  -- make release
```

### CI/CD Pipeline
```bash
# GitHub Actions example
witness run -s build -k key.pem \
  -a github,git,environment,docker \
  -t https://freetsa.org/tsr \
  -- docker build -t ghcr.io/${{ github.repository }}:${{ github.sha }} .
```

### With Timestamp Server
```bash
# Add trusted timestamp
witness run -s build -k key.pem \
  -a git \
  -t https://freetsa.org/tsr \
  -- go build ./...
```

### Archivista Integration
```bash
# Store in Archivista
witness run -s build -k key.pem \
  -a git,product \
  --enable-archivista \
  --archivista-server https://archivista.example.com \
  -- make build
```

## Key Management

### File-based Key
```bash
# Generate key
openssl genrsa -out build-key.pem 4096
openssl rsa -in build-key.pem -pubout -out build-pub.pem

# Use key
witness run -s build -k build-key.pem -a git -- make
```

### KMS Integration
```bash
# AWS KMS
witness run -s build \
  --signer-kms-ref awskms:///arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  -a git -- make

# GCP KMS
witness run -s build \
  --signer-kms-ref gcpkms://projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey \
  -a git -- make
```

### Sigstore Keyless
```bash
# With Fulcio
witness run -s build \
  --signer-fulcio-url https://fulcio.sigstore.dev \
  --signer-fulcio-oidc-issuer https://oauth2.sigstore.dev/auth \
  -a git -- make
```

## Tips

1. **Always use meaningful step names** - They're included in attestations
2. **Combine attestors** for comprehensive provenance
3. **Use output files** (`-o`) for debugging and archival
4. **Add timestamp servers** for long-term verification
5. **Filter sensitive environment variables** when using the environment attestor
6. **Use glob patterns** with material/product attestors for better control

## Troubleshooting

If a command fails:
1. Check the attestor is appropriate for your environment (e.g., aws needs EC2)
2. Verify your signing key permissions
3. Use `--help-attestor <name>` for attestor-specific help
4. Check attestor-specific flags with `witness run --help`