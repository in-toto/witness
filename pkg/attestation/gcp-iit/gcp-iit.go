package gcpiit

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gitlab.com/testifysec/witness-cli/pkg/attestation"
	"gitlab.com/testifysec/witness-cli/pkg/attestation/jwt"
)

const (
	Name    = "gcp-iit"
	Type    = "https://witness.testifysec.com/attestation/gcp-iit/v0.0.1"
	jwksUrl = "https://www.googleapis.com/oauth2/v3/certs"

	defaultIdentityTokenHost     = "metadata.google.internal"
	identityTokenURLPathTemplate = "/computeMetadata/v1/instance/service-accounts/%s/identity"
	identityTokenAudience        = "witness-node-attestor" //nolint: gosec // false positive
	defaultServiceAccount        = "default"
	TokenUrl                     = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=witness-node-attestor&format=full&licenses=TRUE"
	InstanceMetadataUrl          = "http://metadata.google.internal/computeMetadata/v1/instance/"
	InstanceAttributesUrl        = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"
	ProjectMetadataUrl           = "http://metadata.google.internal/computeMetadata/v1/project/"
)

func init() {
	attestation.RegisterAttestation(Name, Type, func() attestation.Attestor {
		return New()
	})
}

type ErrNotGCPIIT struct{}

func (e ErrNotGCPIIT) Error() string {
	return "not a GCP IIT JWT"
}

type Attestor struct {
	JWT                       *jwt.Attestor `json:"jwt"`
	ProjectID                 string        `json:"project_id"`
	ProjectNumber             string        `json:"project_number"`
	InstanceZone              string        `json:"zone"`
	InstanceID                string        `json:"instance_id"`
	InstanceHostname          string        `json:"instance_hostname"`
	InstanceCreationTimestamp string        `json:"instance_creation_timestamp"`
	InstanceConfidentiality   string        `json:"instance_confidentiality"`
	LicenceID                 []string      `json:"licence_id"`
	TokenEmail                string        `json:"email"`
	isWorkloadIdentity        bool          `json:"-"`
	ClusterName               string        `json:"cluster_name"`
	ClusterUID                string        `json:"cluster_uid"`
	ClusterLocation           string        `json:"cluster_location"`

	subjects map[string]crypto.DigestSet
}

func New() *Attestor {
	return &Attestor{
		subjects: make(map[string]crypto.DigestSet),
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {

	tokenURL := identityTokenURL(defaultIdentityTokenHost, defaultServiceAccount)

	identityToken, err := getMetadata(tokenURL)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to retrieve valid identity token: %v", err)
	}

	it := string(identityToken)

	a.JWT = jwt.New(jwt.WithToken(it), jwt.WithJWKSUrl(jwksUrl))
	if err := a.JWT.Attest(ctx); err != nil {
		return err
	}

	a.TokenEmail = a.JWT.Claims["email"].(string)

	if a.JWT.Claims["google"] == nil {
		a.isWorkloadIdentity = true
	}

	if !a.isWorkloadIdentity {
		googClaim := a.JWT.Claims["google"].(map[string]interface{})
		a.ProjectID = googClaim["project_id"].(string)
		a.ProjectNumber = googClaim["project_number"].(string)
		a.InstanceZone = googClaim["zone"].(string)
		a.InstanceID = googClaim["instance_id"].(string)
		a.InstanceHostname = googClaim["instance_name"].(string)
		a.InstanceCreationTimestamp = googClaim["instance_creation_timestamp"].(string)
		a.InstanceConfidentiality = googClaim["instance_confidentiality"].(string)
		a.LicenceID = googClaim["licence_id"].([]string)
	} else {
		a.getInstanceData()
	}

	instanceIDSubject, err := crypto.CalculateDigestSet([]byte(a.InstanceID), ctx.Hashes())
	if err != nil {
		return err
	}
	a.subjects[a.InstanceID] = instanceIDSubject

	instanceHostnameSubject, err := crypto.CalculateDigestSet([]byte(a.InstanceHostname), ctx.Hashes())
	if err != nil {
		return err
	}
	a.subjects[a.InstanceHostname] = instanceHostnameSubject

	projectIDSubject, err := crypto.CalculateDigestSet([]byte(a.ProjectID), ctx.Hashes())
	if err != nil {
		return err
	}
	a.subjects[a.ProjectID] = projectIDSubject

	projectNumberSubject, err := crypto.CalculateDigestSet([]byte(a.ProjectNumber), ctx.Hashes())
	if err != nil {
		return err
	}

	a.subjects[a.ProjectNumber] = projectNumberSubject

	clusterUIDSubejct, err := crypto.CalculateDigestSet([]byte(a.ClusterUID), ctx.Hashes())
	if err != nil {
		return err
	}

	a.subjects[a.ClusterUID] = clusterUIDSubejct

	return nil
}

func (a *Attestor) getInstanceData() {
	endpoints := map[string]string{
		"hostname":         InstanceMetadataUrl + "hostname",
		"id":               InstanceMetadataUrl + "id",
		"zone":             InstanceMetadataUrl + "zone",
		"cluster-name":     InstanceMetadataUrl + "attributes/cluster-name",
		"cluster-uid":      InstanceMetadataUrl + "attributes/cluster-uid",
		"cluster-location": InstanceMetadataUrl + "attributes/cluster-location",
		"project-id":       InstanceMetadataUrl + "project/project-id",
		"project-number":   InstanceMetadataUrl + "project/numeric-project-id",
	}

	metadata := make(map[string]string)

	for k, v := range endpoints {
		data, err := getMetadata(v)
		if err != nil {
			fmt.Println(err)
			continue
		}
		metadata[k] = string(data)
	}

	a.ClusterName = metadata["cluster-name"]
	a.ClusterUID = metadata["cluster-uid"]
	a.ClusterLocation = metadata["cluster-location"]
	a.InstanceHostname = metadata["hostname"]
	a.InstanceID = metadata["id"]
	a.InstanceZone = metadata["zone"]

	projID, projNum, err := parseJWTProjectInfo(a.JWT)
	if err != nil {
		fmt.Printf("unable to parse JWT project info: %v\n", err)
	}

	a.ProjectID = projID
	a.ProjectNumber = projNum

}

func (a *Attestor) Subjects() map[string]crypto.DigestSet {
	return a.subjects
}

func getMetadata(url string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code for route: %d", resp.StatusCode)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// identityTokenURL creates the URL to find an instance identity document given the
// host of the GCP metadata server and the service account the instance is running as.
func identityTokenURL(host, serviceAccount string) string {
	query := url.Values{}
	query.Set("audience", identityTokenAudience)
	query.Set("format", "full")
	url := &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     fmt.Sprintf(identityTokenURLPathTemplate, serviceAccount),
		RawQuery: query.Encode(),
	}
	return url.String()
}

func parseJWTProjectInfo(jwt *jwt.Attestor) (string, string, error) {
	if jwt.Claims["email"] == nil {
		return "", "", fmt.Errorf("unable to find email claim")
	}

	email := jwt.Claims["email"].(string)

	stings := strings.Split(email, "@")
	if len(stings) != 2 {
		return "", "", fmt.Errorf("unable to parse email: %s", email)
	}

	domain := stings[1]

	projectInfo := strings.Split(domain, ".")[0]
	projectInfoSplit := strings.Split(projectInfo, "-")
	projectID := projectInfoSplit[len(projectInfoSplit)-1]
	projectName := strings.Join(projectInfoSplit[:len(projectInfoSplit)-1], "-")

	return projectID, projectName, nil
}
