# GCP Instance Identity Attestor

The GCP Instance Identity Attestor communicates with the GCP metadata server to collect information
about the instance Witness is being exected on. The instance identity JWT's signature is validated
against Google's JWKS to ensure authenticity.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `instanceid` | ID of the Google Compute instance Witness was executed on |
| `instancename` | Name of the Compute instance Witness was executed on |
| `projectid` | The ID of the project that the instance belonged to |
| `projectnumber` | Number of the project that the instance belonged to |
| `clusteruid` | UID of the cluster if the execution enviornment was a GKE clister |
