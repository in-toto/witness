// Copyright 2021 The Witness Contributors
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

package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/file"
	"github.com/in-toto/witness/options"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_VerifyCmd(t *testing.T) {
	cmd := VerifyCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "verify", cmd.Use)
	assert.Equal(t, true, cmd.SilenceErrors)
	assert.Equal(t, true, cmd.SilenceUsage)
	
	// Test flag addition
	flag := cmd.Flags().Lookup("policy")
	require.NotNil(t, flag, "Expected policy flag to be added")
	
	// Test help output
	require.NotEmpty(t, cmd.Long)
	
	// Basic validation of the command structure
}

func TestVerifyCmdDeprecatedFlag(t *testing.T) {
	// Create a buffer to capture log output
	var logBuffer bytes.Buffer
	
	// Get original logger and restore it after test
	originalLogger := log.GetLogger()
	defer log.SetLogger(originalLogger)
	
	// Create a test logger that writes to our buffer
	testLog := logrus.New()
	testLog.SetOutput(&logBuffer)
	testLogger := &logrusLogger{l: testLog}
	log.SetLogger(testLogger)
	
	// Create the command
	cmd := VerifyCmd()
	
	// Set the deprecated flag
	err := cmd.Flags().Set("policy-ca", "dummy.pem")
	require.NoError(t, err)
	
	// Execute the command with dummy args (will error but that's expected)
	err = cmd.RunE(cmd, []string{})
	require.NoError(t, err)
	
	// Verify the warning was logged
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "The flag `--policy-ca` is deprecated")
}

func TestRunVerifyBasicValidation(t *testing.T) {
	// Test missing key, CA and verifier
	err := runVerify(context.Background(), options.VerifyOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must supply either a public key, CA certificates or a verifier")
	
	// Test missing attestation source
	err = runVerify(context.Background(), options.VerifyOptions{
		PolicyCARootPaths: []string{"some-path"}, // Mock a CA path to pass initial validation
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must either specify attestation file paths or enable archivista")
}

func TestVerifyPolicyWithFulcio(t *testing.T) {
	workingDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "fulcio.pem"), []byte(fulciopem), 0644)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "freetsa.pem"), []byte(freetsapem), 0644)
	if err != nil {
		panic(err)
	}

	vo := options.VerifyOptions{
		PolicyFilePath:         filepath.Join(cwd, "../test/fulcio-policy-signed.json"),
		PolicyTimestampServers: []string{filepath.Join(workingDir, "freetsa.pem")},
		PolicyCARootPaths:      []string{filepath.Join(workingDir, "fulcio.pem")},
		AttestationFilePaths:   []string{filepath.Join(cwd, "../test/test.json")},
		ArtifactFilePath:       filepath.Join(cwd, "../test/test.txt"),
		PolicyCommonName:       "*",
		PolicyURIs:             []string{"*"},
		PolicyDNSNames:         []string{"*"},
		PolicyEmails:           []string{"*"},
		PolicyOrganizations:    []string{"*"},
	}

	require.NoError(t, runVerify(context.Background(), vo))
}

// Same test but deliberately missing the CA file path for verifying the policy
func TestVerifyPolicyWrongCAFile(t *testing.T) {
	workingDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	// we're going to write the wrong CA file here to ensure that it fails
	err = os.WriteFile(filepath.Join(workingDir, "badca.pem"), []byte(freetsapem), 0644)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(workingDir, "freetsa.pem"), []byte(freetsapem), 0644)
	if err != nil {
		panic(err)
	}

	vo := options.VerifyOptions{
		PolicyFilePath:         filepath.Join(cwd, "../test/fulcio-policy-signed.json"),
		PolicyTimestampServers: []string{filepath.Join(workingDir, "freetsa.pem")},
		PolicyCARootPaths:      []string{filepath.Join(workingDir, "badca.pem")},
		AttestationFilePaths:   []string{filepath.Join(cwd, "../test/test.json")},
		ArtifactFilePath:       filepath.Join(cwd, "../test/test.txt"),
	}

	require.ErrorContains(t, runVerify(context.Background(), vo), "failed to verify policy: attestors failed with error messages\nfailed to verify policy signature: could not verify policy: no valid signatures for the provided verifiers found for keyids:\n")
}

func TestRunVerifyCA(t *testing.T) {
	ca, intermediates, leafcert, leafkey := fullChain(t)

	so := options.SignerOptions{}
	so["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
		func(sp signer.SignerProvider) (signer.SignerProvider, error) {
			fsp := sp.(file.FileSignerProvider)
			fsp.KeyPath = leafkey.Name()
			fsp.IntermediatePaths = []string{intermediates[0].Name()}
			fsp.CertPath = leafcert.Name()
			return fsp, nil
		},
	}

	signers, err := loadSigners(context.Background(), so, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
	require.NoError(t, err)

	caBytes, err := os.ReadFile(ca.Name())
	require.NoError(t, err)

	policy := makepolicyCA(t, caBytes)
	signedPolicy, pub := signPolicyRSA(t, policy)

	workingDir := t.TempDir()
	attestationDir := t.TempDir()

	policyFilePath := filepath.Join(workingDir, "signed-policy.json")
	require.NoError(t, os.WriteFile(policyFilePath, signedPolicy, 0644))

	policyPubFilePath := filepath.Join(workingDir, "policy-pub.pem")
	require.NoError(t, os.WriteFile(policyPubFilePath, pub, 0644))

	artifactPath := filepath.Join(workingDir, "test.txt")
	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1FilePath := filepath.Join(attestationDir, "step01.json")
	s1RunOptions := options.RunOptions{
		SignerOptions: so,
		WorkingDir:    workingDir,
		Attestations:  []string{},
		OutFilePath:   s1FilePath,
		StepName:      "step01",
		Tracing:       false,
	}

	require.NoError(t, runRun(context.Background(), s1RunOptions, step1Args, signers...))

	subjects := []string{}
	artifactDigest, err := cryptoutil.CalculateDigestSetFromFile(artifactPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2FilePath := filepath.Join(attestationDir, "step02.json")
	s2RunOptions := options.RunOptions{
		SignerOptions: so,
		WorkingDir:    workingDir,
		Attestations:  []string{},
		OutFilePath:   s2FilePath,
		StepName:      "step02",
		Tracing:       false,
	}

	require.NoError(t, runRun(context.Background(), s2RunOptions, step2Args, signers...))

	vo := options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		ArtifactFilePath:     artifactPath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))

	// test that verify works without artifactfilepath but the subject of the modified articact also provided
	artifactDigest, err = cryptoutil.CalculateDigestSetFromFile(artifactPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	vo = options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))
}

func TestRunVerifyKeyPair(t *testing.T) {
	logger := newLogger()
	log.SetLogger(logger)

	policy, funcPriv := makepolicyRSAPub(t)
	signedPolicy, pub := signPolicyRSA(t, policy)
	workingDir := t.TempDir()
	attestationDir := t.TempDir()
	policyFilePath := filepath.Join(workingDir, "signed-policy.json")
	require.NoError(t, os.WriteFile(policyFilePath, signedPolicy, 0644))

	policyPubFilePath := filepath.Join(workingDir, "policy-pub.pem")
	require.NoError(t, os.WriteFile(policyPubFilePath, pub, 0644))

	funcPrivFilepath := filepath.Join(workingDir, "func-priv.pem")
	require.NoError(t, os.WriteFile(funcPrivFilepath, funcPriv, 0644))

	so := options.SignerOptions{}
	so["file"] = []func(signer.SignerProvider) (signer.SignerProvider, error){
		func(sp signer.SignerProvider) (signer.SignerProvider, error) {
			fsp := sp.(file.FileSignerProvider)
			fsp.KeyPath = funcPrivFilepath
			return fsp, nil
		},
	}

	signers, err := loadSigners(context.Background(), so, options.KMSSignerProviderOptions{}, map[string]struct{}{"file": {}})
	require.NoError(t, err)

	artifactPath := filepath.Join(workingDir, "test.txt")
	step1Args := []string{
		"bash",
		"-c",
		"echo 'test01' > test.txt",
	}

	s1FilePath := filepath.Join(attestationDir, "step01.json")
	s1RunOptions := options.RunOptions{
		SignerOptions: so,
		WorkingDir:    workingDir,
		Attestations:  []string{},
		OutFilePath:   s1FilePath,
		StepName:      "step01",
		Tracing:       false,
	}

	require.NoError(t, runRun(context.Background(), s1RunOptions, step1Args, signers...))

	subjects := []string{}
	artifactDigest, err := cryptoutil.CalculateDigestSetFromFile(artifactPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	step2Args := []string{
		"bash",
		"-c",
		"echo 'test02' >> test.txt",
	}

	s2FilePath := filepath.Join(attestationDir, "step02.json")
	s2RunOptions := options.RunOptions{
		SignerOptions: so,
		WorkingDir:    workingDir,
		Attestations:  []string{},
		OutFilePath:   s2FilePath,
		StepName:      "step02",
		Tracing:       false,
	}

	require.NoError(t, runRun(context.Background(), s2RunOptions, step2Args, signers...))

	vo := options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		ArtifactFilePath:     artifactPath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))

	// test that verify works without artifactfilepath but the subject of the modified articact also provided
	artifactDigest, err = cryptoutil.CalculateDigestSetFromFile(artifactPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	for _, digest := range artifactDigest {
		subjects = append(subjects, digest)
	}

	vo = options.VerifyOptions{
		KeyPath:              policyPubFilePath,
		AttestationFilePaths: []string{s1FilePath, s2FilePath},
		PolicyFilePath:       policyFilePath,
		AdditionalSubjects:   subjects,
	}

	require.NoError(t, runVerify(context.Background(), vo))
}

func signPolicyRSA(t *testing.T, p []byte) (signedPolicy []byte, pub []byte) {
	sign, _, pub, _, err := createTestRSAKey()
	require.NoError(t, err)
	reader := bytes.NewReader(p)
	outBytes := []byte{}
	writer := bytes.NewBuffer(outBytes)
	require.NoError(t, witness.Sign(reader, "https://witness.testifysec.com/policy/v0.1", writer, dsse.SignWithSigners(sign)))
	return writer.Bytes(), pub
}

func makepolicyCA(t *testing.T, ca []byte) []byte {
	r := bytes.NewReader(ca)
	verifier, err := cryptoutil.NewVerifierFromReader(r)
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	functionary := policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			CommonName:    "*",
			DNSNames:      []string{"*"},
			Emails:        []string{"*"},
			Organizations: []string{"*"},
			URIs:          []string{"*"},
			Roots:         []string{keyID},
		},
	}

	root := policy.Root{
		Certificate: ca,
	}

	roots := map[string]policy.Root{}
	roots[keyID] = root
	policy := makepolicy(t, functionary, policy.PublicKey{}, roots)
	return policy
}

func makepolicyRSAPub(t *testing.T) ([]byte, []byte) {
	_, ver, pub, fpriv, err := createTestRSAKey()
	require.NoError(t, err)
	keyID, err := ver.KeyID()
	require.NoError(t, err)
	functionary := policy.Functionary{
		Type:        "PublicKey",
		PublicKeyID: keyID,
	}

	pk := policy.PublicKey{
		KeyID: keyID,
		Key:   pub,
	}

	p := makepolicy(t, functionary, pk, nil)
	return p, fpriv
}

func makepolicy(t *testing.T, functionary policy.Functionary, publicKey policy.PublicKey, roots map[string]policy.Root) []byte {
	step01 := policy.Step{
		Name:          "step01",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
	}

	step02 := policy.Step{
		Name:          "step02",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
		ArtifactsFrom: []string{"step01"},
	}

	p := policy.Policy{
		Expires:    metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		PublicKeys: map[string]policy.PublicKey{},
		Steps:      map[string]policy.Step{},
	}

	if functionary.CertConstraint.Roots != nil {
		p.Roots = roots
	}

	p.Steps = make(map[string]policy.Step)
	p.Steps[step01.Name] = step01
	p.Steps[step02.Name] = step02

	if publicKey.KeyID != "" {
		p.PublicKeys[publicKey.KeyID] = publicKey
	}

	pb, err := json.MarshalIndent(p, "", "  ")
	require.NoError(t, err)
	return pb
}

func createTestRSAKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keybits)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})

	privKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return signer, verifier, pemBytes, privKeyBytes, nil
}

const (
	fulciopem = `-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7
XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex
X69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY
wB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ
KsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM
WP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9
TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ
-----END CERTIFICATE-----
`
	freetsapem = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`
)