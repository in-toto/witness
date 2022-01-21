// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws_iid

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

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

//These will be configurable in the future
const (
	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
	//https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html
	//The following AWS public certificate is for all AWS Regions, except Hong Kong, Bahrain, China, and GovCloud.
	awsCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	ec2metadata.EC2InstanceIdentityDocument
	subjects  map[string]cryptoutil.DigestSet
	hashes    []crypto.Hash
	session   session.Session
	conf      *aws.Config
	RawIID    string `json:"rawiid"`
	RawSig    string `json:"rawsig"`
	PublicKey string `json:"publickey"`
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

	err := a.getIID()
	if err != nil {
		return err
	}

	err = a.Verify()
	if err != nil {
		return err
	}

	subjects := make(map[string]string)
	subjects[fmt.Sprintf("instanceid:%s", a.EC2InstanceIdentityDocument.InstanceID)] = a.EC2InstanceIdentityDocument.InstanceID
	subjects[fmt.Sprintf("accountid:%s", a.EC2InstanceIdentityDocument.AccountID)] = a.EC2InstanceIdentityDocument.AccountID
	subjects[fmt.Sprintf("imageid:%s", a.EC2InstanceIdentityDocument.ImageID)] = a.EC2InstanceIdentityDocument.ImageID
	subjects[fmt.Sprintf("privateip:%s", a.EC2InstanceIdentityDocument.PrivateIP)] = a.EC2InstanceIdentityDocument.PrivateIP

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
	iid, err := svc.GetDynamicData(docPath)
	if err != nil {
		return fmt.Errorf("failed to get instance identity document: %v", err)
	}

	sig, err := svc.GetDynamicData(sigPath)
	if err != nil {
		return fmt.Errorf("failed to get signature: %v", err)
	}

	a.RawIID = iid
	a.RawSig = sig

	err = json.Unmarshal([]byte(a.RawIID), &a.EC2InstanceIdentityDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal iid: %v", err)
	}

	return nil
}

func (a *Attestor) Verify() error {

	if len(a.RawIID) == 0 || len(a.RawSig) == 0 {
		return nil
	}

	docHash := sha256.Sum256([]byte(a.RawIID))
	sigBytes, err := base64.StdEncoding.DecodeString(a.RawSig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	pubKey, err := getAWSCAPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get AWS public key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	a.PublicKey = string(pem)

	if err != nil {
		return fmt.Errorf("failed to encode public key: %v", err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes)
	if err != nil {
		fmt.Printf("failed to verify signature: %v", err)
		return nil
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

func getAWSCAPublicKey() (*rsa.PublicKey, error) {

	block, rest := pem.Decode([]byte(awsCACertPEM))
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert.PublicKey.(*rsa.PublicKey), nil

}
