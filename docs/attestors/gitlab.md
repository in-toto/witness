# GitLab Attestor

The GitLab Attestor records information about the GitLab CI/CD job execution in which
TestifySec Witness was run. Witness verifies the JWT (JSON Web Token) provided in `CI_JOB_JWT` against the
instance's JWKS (JSON Web Key Ste) to ensure authenticity at execution time.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `pipelineurl` | URL of the CI/CD pipeline to which this job belonged  |
| `joburl` | URL of the CI/CD job that this attestor describes |
| `projecturl` | URL of the project that owns the CI/CD pipeline and job |
