# AWS Instance Identity Attestor

The AWS Instance Identity Attestor communicates with the AWS Instance Metadata to collect
information about the instance Witness is being executed on. The documents signature is
verified with the AWS RSA public certificate available [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html).
This currently does not work for the Hong Kong, Bahrain, Cape Town, Milan, China, or
GovCloud regions.

## Subjects

| Subject | Description |
| ------- | ----------- |
| `instanceid` | The ID of the instance Witness was executed on |
| `accountid` | ID of the account that owns the AWS instance |
| `imageid` | ID of the AMI the instance was running at time of execution |
| `privateip` | IP of the instance at time of execution |
