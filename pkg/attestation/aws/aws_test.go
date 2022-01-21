package aws

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/witness/pkg/attestation"
	"github.com/testifysec/witness/pkg/cryptoutil"
)

const iid = `{
    "devpayProductCodes" : null,
    "marketplaceProductCodes" : [ "1abc2defghijklm3nopqrs4tu" ], 
    "availabilityZone" : "us-west-2b",
    "privateIp" : "10.158.112.84",
    "version" : "2017-09-30",
    "instanceId" : "i-1234567890abcdef0",
    "billingProducts" : null,
    "instanceType" : "t2.micro",
    "accountId" : "123456789012",
    "imageId" : "ami-5fb8c835",
    "pendingTime" : "2016-11-19T16:32:11Z",
    "architecture" : "x86_64",
    "kernelId" : null,
    "ramdiskId" : null,
    "region" : "us-west-2"
}`

const iam = `{
	"InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/witness-test-role",
	"InstanceProfileId": "AIPAJQKX7Z2L7X7XJ6XZ",
	"devpayProductCodes": null,
	"marketplaceProductCodes": null,
	"LastUpdated": "2019-01-01T00:00:00Z",
	"Code": "Success"
}`

type testresp struct {
	path string
	resp string
}

func GetTestResponses() []testresp {
	return []testresp{
		{"/latest/dynamic/instance-identity/document", iid},
		{"/latest/meta-data/iam/info", iam},
	}
}

func initTestServer(testresponses []testresp) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, resp := range testresponses {
			if r.URL.Path == resp.path {
				w.Write([]byte(resp.resp))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestAttestor_Name(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Expected Name to be %s, got %s", Name, a.Name())
	}
}

func TestAttestor_Type(t *testing.T) {
	a := New()
	if a.Type() != Type {
		t.Errorf("Expected Type to be %s, got %s", Type, a.Type())
	}

}

func TestAttestor_RunType(t *testing.T) {
	a := New()
	if a.RunType() != RunType {
		t.Errorf("Expected RunType to be %s, got %s", RunType, a.RunType())
	}

}

func TestAttestor_Attest(t *testing.T) {
	server := initTestServer(GetTestResponses())

	defer server.Close()

	endpoint := server.URL + "/latest"
	conf := aws.NewConfig().WithEndpoint(endpoint)
	sess, err := session.NewSession()
	if err != nil {
		t.Error(err)
	}

	a := &Attestor{
		session:  *sess,
		conf:     conf,
		subjects: make(map[string]cryptoutil.DigestSet),
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)

}

func TestAttestor_getIID(t *testing.T) {
	server := initTestServer(GetTestResponses())
	defer server.Close()

	endpoint := server.URL + "/latest"
	conf := aws.NewConfig().WithEndpoint(endpoint)
	sess, err := session.NewSession()
	if err != nil {
		t.Error(err)
	}

	a := &Attestor{
		session: *sess,
		conf:    conf,
	}

	err = a.getIID()
	require.NoError(t, err)

}

func TestAttestor_getIAM(t *testing.T) {
	server := initTestServer(GetTestResponses())
	defer server.Close()

	endpoint := server.URL + "/latest"
	conf := aws.NewConfig().WithEndpoint(endpoint)
	sess, err := session.NewSession()
	if err != nil {
		t.Error(err)
	}

	a := &Attestor{
		session: *sess,
		conf:    conf,
	}

	err = a.getIAM()
	require.NoError(t, err)

}

func TestAttestor_Subjects(t *testing.T) {
	server := initTestServer(GetTestResponses())
	defer server.Close()

	endpoint := server.URL + "/latest"
	conf := aws.NewConfig().WithEndpoint(endpoint)
	sess, err := session.NewSession()
	require.NoError(t, err)

	a := &Attestor{
		session:  *sess,
		conf:     conf,
		subjects: map[string]cryptoutil.DigestSet{},
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	a.Attest(ctx)

	res := a.Subjects()

	if len(res) != 8 {
		t.Errorf("Expected 8 subjects, got %d", len(res))
	}

	imageid := sha256.Sum256([]byte("ami-5fb8c835"))
	digest := res["image-id"]
	h := digest[crypto.SHA256]
	h2 := hex.EncodeToString(imageid[:])
	if h != h2 {
		t.Errorf("Expected %s, got %s", h, h2)
	}

}

func Test_getAWSPublicKey(t *testing.T) {
	key, err := getAWSCAPublicKey()
	require.NoError(t, err)
	if key == nil {
		t.Error("Expected key to not be nil")
	}
}
