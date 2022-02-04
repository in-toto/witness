# Gitlab Attestor

The Gitlab attestor records information about the Gitlab CI/CD job execution that
Witness was run in. Witness verifies the JWT provided in `CI_JOB_JWT` against the
instance's JWKS to ensure authenticity at execution time.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `pipelineurl` | Url of the CI/CD pipeline that this job belonged to |
| `joburl` | Url of the CI/CD job that this attestor describes |
| `projecturl` | Url of the project that owns the CI/CD pipeline and job |
