package aws

import (
	"crypto"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const (
	Name    = "aws"
	Type    = "https://witness.testifysec.com/attestation/aws/v0.1"
	RunType = attestation.PreRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	ec2metadata.EC2IAMInfo
	ec2metadata.EC2InstanceIdentityDocument
	subjects map[string]cryptoutil.DigestSet
	hashes   []crypto.Hash
	session  session.Session
	conf     *aws.Config
}

func New() *Attestor {
	sess, err := session.NewSession()
	if err != nil {
		return nil
	}

	conf := &aws.Config{}

	return &Attestor{
		session:  *sess,
		conf:     conf,
		subjects: make(map[string]cryptoutil.DigestSet),
	}

}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()

	a.getIAM()
	a.getIID()

	subjects := make(map[string]string)
	subjects["instance-id"] = a.EC2InstanceIdentityDocument.InstanceID
	subjects["account-id"] = a.EC2InstanceIdentityDocument.AccountID
	subjects["image-id"] = a.EC2InstanceIdentityDocument.ImageID
	subjects["kernel-id"] = a.EC2InstanceIdentityDocument.KernelID
	subjects["ramdisk-id"] = a.EC2InstanceIdentityDocument.RamdiskID
	subjects["private-ip"] = a.EC2InstanceIdentityDocument.PrivateIP
	subjects["iam-instance-profile-id"] = a.EC2IAMInfo.InstanceProfileArn
	subjects["iam-instance-profile-arn"] = a.EC2IAMInfo.InstanceProfileArn

	for k, v := range subjects {
		subj, err := cryptoutil.CalculateDigestSetFromBytes([]byte(v), ctx.Hashes())
		if err != nil {
			continue
		}
		a.subjects[k] = subj
	}

	return nil
}

func (a *Attestor) getIID() error {
	svc := ec2metadata.New(&a.session, a.conf)
	iid, err := svc.GetInstanceIdentityDocument()
	if err != nil {
		return err
	}

	a.EC2InstanceIdentityDocument = iid
	return nil
}

func (a *Attestor) getIAM() error {
	svc := ec2metadata.New(&a.session, a.conf)
	iam, err := svc.IAMInfo()
	if err != nil {
		return err
	}
	a.EC2IAMInfo = iam
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
