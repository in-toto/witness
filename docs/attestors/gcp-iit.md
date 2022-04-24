# GCP Instance Identity Attestor

The Google Cloud Platform (GCP) Instance Identity Attestor communicates with the GCP metadata server to collect information
about the instance on which TestifySec Witness is being exected. The instance identity JSON Web Token signature is validated
against Google's JWKS (JSON Web Key Set) to ensure authenticity.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `instanceid` | ID of the Google Compute instance on which Witness was executed |
| `instancename` | Name of the Compute instance on which Witness was executed |
| `projectid` | The ID of the project to which the instance belonged |
| `projectnumber` | Number of the project to which the instance belonged |
| `clusteruid` | UID of the cluster if the execution environment was a Google Kubernetes Engine (GKE) cluster |
