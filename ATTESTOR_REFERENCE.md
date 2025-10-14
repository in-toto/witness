# Witness Attestor Reference Guide

This guide provides developer-friendly descriptions of all available attestors in Witness, helping you choose the right attestors for your software supply chain security needs.

## Quick Reference Table

| Attestor | Purpose | Run Type | Use When |
|----------|---------|----------|----------|
| aws | Captures AWS EC2 instance metadata | Pre-Material | Proving builds ran on AWS infrastructure |
| command-run | Records command execution details | Execute | Auditing build commands and outputs |
| docker | Records Docker image creation | Post-Product | Container build provenance |
| environment | Captures environment variables | Pre-Material | Build environment documentation |
| gcp-iit | Captures GCP instance identity | Pre-Material | Proving builds ran on GCP infrastructure |
| git | Records Git repository state | Pre-Material | Source code provenance |
| github | Captures GitHub Actions context | Pre-Material | GitHub CI/CD provenance |
| gitlab | Captures GitLab CI context | Pre-Material | GitLab CI/CD provenance |
| jenkins | Captures Jenkins build context | Pre-Material | Jenkins CI/CD provenance |
| jwt | Verifies and records JWT claims | Pre-Material | Identity verification |
| k8smanifest | Records Kubernetes manifests | Post-Product | K8s deployment tracking |
| link | Creates in-toto Link attestations | Post-Product | in-toto compatibility |
| lockfiles | Captures dependency lockfiles | Pre-Material | Dependency verification |
| material | Records input artifacts | Material | Input file tracking |
| maven | Records Maven build info | Post-Product | Java build provenance |
| oci | Records OCI registry artifacts | Post-Product | Container registry provenance |
| omnitrail | Creates OmniTrail envelopes | Pre-Material | Cross-platform artifact tracking |
| policyverify | Records policy verification | Verify | Policy enforcement validation |
| product | Records output artifacts | Product | Output file tracking |
| sarif | Captures security scan results | Post-Product | Security findings tracking |
| sbom | Records SBOM documents | Post-Product | Dependency transparency |
| secretscan | Detects potential secrets | Pre-Material | Security hygiene |
| slsa | Generates SLSA provenance | Post-Product | SLSA compliance |
| system-packages | Records system packages | Pre-Material | System dependencies |
| vex | Records vulnerability info | Post-Product | Vulnerability management |

## Detailed Attestor Descriptions

### AWS Instance Identity Attestor (`aws`)

**What it does:** Captures cryptographically signed metadata about the AWS EC2 instance where your build is running, including instance ID, region, account ID, and AMI ID.

**When to use:**
- Ensuring builds only run on approved AWS infrastructure
- Compliance requirements for cloud workload attestation
- Multi-cloud deployments needing infrastructure verification

**Example:**
```bash
witness run -a aws -s build -- make build
```

**Key considerations:**
- Only works on AWS EC2 instances
- Requires access to instance metadata service
- Regional limitations in some AWS partitions

### Command Run Attestor (`command-run`)

**What it does:** Records comprehensive details about command execution including arguments, exit codes, stdout/stderr, and (optionally on Linux) system call tracing.

**When to use:**
- Auditing build commands for security reviews
- Debugging build failures with complete context
- Compliance requirements for build transparency
- Detecting unexpected file access or network calls (with tracing)

**Example:**
```bash
# Basic command recording
witness run -s build -- make build

# With system call tracing (Linux only)
witness run -s build --trace -- make build
```

**Key considerations:**
- Automatically included when running commands
- Tracing adds performance overhead
- Captures all output - be careful with secrets

### Docker Attestor (`docker`)

**What it does:** Automatically detects and records metadata about Docker images created during your build process, including digests, tags, and layer information.

**When to use:**
- Container build pipelines
- Multi-stage Docker builds
- Ensuring specific base images were used
- Container supply chain security

**Example:**
```bash
witness run -a docker -s build -- docker build -t myapp:v1.0 .
```

**Key considerations:**
- Requires Docker daemon access
- Detects images created by Docker operations
- Supports multi-architecture manifests

### Environment Attestor (`environment`)

**What it does:** Captures environment variables and system information (OS, hostname, user) with built-in protection for sensitive values.

**When to use:**
- Documenting build environment for reproducibility
- Verifying builds ran with correct configuration
- Debugging environment-specific issues
- Compliance documentation

**Example:**
```bash
# Default (obfuscates sensitive vars)
witness run -a environment -s setup -- ./configure

# Filter out sensitive vars completely
witness run -a environment --env-filter-sensitive-vars -s setup -- ./configure

# Add custom sensitive patterns
witness run -a environment --env-add-sensitive-key 'API_*' -s setup -- ./configure
```

**Key considerations:**
- Automatically obfuscates common sensitive variables
- Can filter or obfuscate based on patterns
- May contain sensitive data even with protections

### Git Attestor (`git`)

**What it does:** Captures complete Git repository state including commit info, branch, tags, remotes, signatures, and working directory status.

**When to use:**
- Source code provenance for any git-based project
- Verifying builds from specific commits/branches
- Detecting uncommitted changes in builds
- Tracking repository signatures

**Example:**
```bash
witness run -a git -s source -- go build ./...
```

**Key considerations:**
- Works in any git repository
- Captures both clean and dirty states
- Includes signature verification status
- Performance impact on large repos

### GitHub Actions Attestor (`github`)

**What it does:** Captures GitHub Actions workflow context including workflow name, job ID, runner info, and repository details.

**When to use:**
- GitHub Actions workflows
- Proving builds ran in GitHub infrastructure
- Workflow provenance and audit trails
- Integration with GitHub security features

**Example:**
```yaml
- name: Build with attestation
  run: witness run -a github -s build -- make build
```

**Key considerations:**
- Only works in GitHub Actions environment
- Automatically detects GitHub context
- Includes actor and trigger information

### GitLab CI Attestor (`gitlab`)

**What it does:** Captures GitLab CI/CD pipeline context including job details, runner info, and project metadata.

**When to use:**
- GitLab CI/CD pipelines
- Proving builds ran in GitLab infrastructure
- Pipeline provenance and audit trails
- GitLab-specific compliance needs

**Example:**
```yaml
build:
  script:
    - witness run -a gitlab -s build -- make build
```

**Key considerations:**
- Only works in GitLab CI environment
- Captures merge request context
- Includes runner tags and metadata

### JWT Attestor (`jwt`)

**What it does:** Verifies and records claims from JWT tokens, supporting OIDC and other JWT-based identity systems.

**When to use:**
- Workload identity verification
- OIDC token attestation
- Federated authentication scenarios
- Zero-trust architectures

**Example:**
```bash
witness run -a jwt -s auth -- ./deploy.sh
```

**Key considerations:**
- Token must be available in environment or file
- Performs signature verification
- Records all token claims

### Kubernetes Manifest Attestor (`k8smanifest`)

**What it does:** Records Kubernetes manifest files (YAML/JSON) used or generated during your build/deployment process.

**When to use:**
- GitOps workflows
- Kubernetes deployment tracking
- Manifest integrity verification
- Configuration drift detection

**Example:**
```bash
witness run -a k8smanifest -s deploy -- kubectl apply -f manifests/
```

**Key considerations:**
- Automatically finds manifest files
- Preserves original formatting
- Supports multiple manifests

### Link Attestor (`link`)

**What it does:** Creates in-toto specification compliant Link attestations, providing compatibility with the in-toto framework.

**When to use:**
- in-toto framework integration
- Step-level attestations in complex pipelines
- Bridging Witness with in-toto tooling
- Legacy system compatibility

**Example:**
```bash
witness run -a link -s build --attestor-link-name "compilation" -- make
```

**Key considerations:**
- Aggregates material and product info
- Exportable as standalone attestation
- Compatible with in-toto verification

### Material Attestor (`material`)

**What it does:** Records cryptographic hashes and metadata for all input files used in a build step.

**When to use:**
- Tracking build inputs
- Verifying source file integrity
- Detecting tampering with inputs
- Complete build reproducibility

**Example:**
```bash
witness run -a material -s build -- go build ./...
```

**Key considerations:**
- Recursively scans directories
- Multiple hash algorithm support
- Handles symlinks appropriately
- Can impact performance on large trees

### Maven Attestor (`maven`)

**What it does:** Records Maven project information, dependencies, and generated artifacts from Maven builds.

**When to use:**
- Java/Maven projects
- Tracking Maven artifact creation
- Java dependency management
- Maven-specific compliance needs

**Example:**
```bash
witness run -a maven -s build -- mvn package
```

**Key considerations:**
- Requires Maven project structure
- Captures POM information
- Records generated artifacts

### OCI Registry Attestor (`oci`)

**What it does:** Records metadata about OCI (Open Container Initiative) artifacts in registries, including manifests and multi-arch images.

**When to use:**
- Container registry operations
- Multi-architecture image builds
- Registry-based artifact management
- Container signing workflows

**Example:**
```bash
witness run -a oci -s push -- crane push image.tar registry.io/myimage:latest
```

**Key considerations:**
- Works with OCI-compliant registries
- Captures manifest details
- Supports manifest lists

### Policy Verify Attestor (`policyverify`)

**What it does:** Records the results of policy verification in SLSA Verification Summary format, showing which policy rules passed or failed.

**When to use:**
- Policy enforcement workflows
- Compliance validation
- Multi-stage verification pipelines
- Audit trail for policy decisions

**Example:**
```bash
witness verify -p policy.json -a policyverify -s verification
```

**Key considerations:**
- Special attestor for verify command
- SLSA VSA format output
- Records detailed verification results

### Product Attestor (`product`)

**What it does:** Records cryptographic hashes and metadata for all output files created during a build step.

**When to use:**
- Tracking build outputs
- Artifact integrity verification
- Release management
- Output tampering detection

**Example:**
```bash
witness run -a product -s build -- make build
```

**Key considerations:**
- Detects new and modified files
- MIME type detection
- Handles binary and text files
- Performance impact on many files

### SARIF Attestor (`sarif`)

**What it does:** Captures and preserves Static Analysis Results Interchange Format (SARIF) files containing security scan results.

**When to use:**
- Security scanning integration
- Static analysis workflows
- Vulnerability tracking
- Security compliance reporting

**Example:**
```bash
witness run -a sarif -s scan -- semgrep --config=auto --sarif -o results.sarif .
```

**Key considerations:**
- Parses SARIF format files
- Preserves complete scan results
- Works with various security tools

### SBOM Attestor (`sbom`)

**What it does:** Records Software Bill of Materials documents in SPDX or CycloneDX formats, capturing dependency information.

**When to use:**
- Dependency transparency requirements
- License compliance workflows
- Supply chain security
- SBOM generation pipelines

**Example:**
```bash
# Generate and attest SBOM
syft . -o cyclonedx-json > sbom.json
witness run -a sbom -s package -- echo "SBOM generated"
```

**Key considerations:**
- Auto-detects SBOM format
- Validates SBOM structure
- Can export as separate attestation

### Secret Scan Attestor (`secretscan`)

**What it does:** Scans files and other attestations for potential secrets using pattern matching, recording findings without exposing actual secret values.

**When to use:**
- Pre-build security checks
- Preventing credential leaks
- Security hygiene enforcement
- CI/CD security gates

**Example:**
```bash
witness run -a secretscan -s scan -- go test ./...
```

**Key considerations:**
- Never stores actual secrets
- Uses Gitleaks patterns
- Scans multiple encoding layers
- Can scan environment variables

### SLSA Provenance Attestor (`slsa`)

**What it does:** Generates SLSA v1.0 compliant provenance by aggregating information from other attestors into the standard format.

**When to use:**
- SLSA compliance requirements
- Standardized build provenance
- Cross-tool provenance sharing
- Supply chain security frameworks

**Example:**
```bash
# Generate with inline attestation
witness run -a slsa -s build -- make build

# Export to separate file
witness run -a slsa --attestor-slsa-export=provenance.json -s build -- make build
```

**Key considerations:**
- Aggregates data from other attestors
- SLSA v1.0 format
- Multiple builder ID support
- Exportable provenance

### System Packages Attestor (`system-packages`)

**What it does:** Records installed system packages (Debian/RPM) and OS information, providing a snapshot of system-level dependencies.

**When to use:**
- Documenting build environments
- System dependency tracking
- Security vulnerability scanning
- Environment reproducibility

**Example:**
```bash
witness run -a system-packages -s setup -- ./configure
```

**Key considerations:**
- Linux-specific (dpkg/rpm)
- May be slow on systems with many packages
- Includes OS distribution info

### VEX Attestor (`vex`)

**What it does:** Records Vulnerability Exploitability eXchange documents that explain the status of vulnerabilities in your software.

**When to use:**
- Vulnerability management workflows
- False positive documentation
- Security exception tracking
- Compliance reporting

**Example:**
```bash
witness run -a vex -s assess -- vexctl create --product pkg:oci/myimage@sha256:abc...
```

**Key considerations:**
- OpenVEX format support
- Links vulnerabilities to products
- Documents vulnerability decisions

## Attestor Run Types Explained

- **Pre-Material**: Runs before recording input materials. Use for environment setup and context capture.
- **Material**: Records input artifacts. Automatically captures files used in the build.
- **Execute**: Runs during command execution. Captures runtime information.
- **Product**: Records output artifacts. Automatically captures files created or modified.
- **Post-Product**: Runs after products are recorded. Use for additional metadata or artifact processing.
- **Verify**: Special type for policy verification workflows.

## Best Practices

1. **Layer attestors** for comprehensive coverage:
   ```bash
   witness run -a environment,git,sbom,slsa -s build -- make release
   ```

2. **Use specific attestors** for your infrastructure:
   - AWS builds: include `aws`
   - GitHub Actions: include `github`
   - Container builds: include `docker` and `oci`

3. **Security considerations:**
   - Always use `secretscan` in security-sensitive pipelines
   - Configure `environment` attestor to protect sensitive vars
   - Review `command-run` output for accidental secret exposure

4. **Performance optimization:**
   - Tracing adds overhead - use only when needed
   - Large directory scans impact material/product attestors
   - System package scanning can be slow

5. **Policy integration:**
   - Design policies that verify critical attestors
   - Use attestor data for policy decisions
   - Combine multiple attestors for stronger guarantees