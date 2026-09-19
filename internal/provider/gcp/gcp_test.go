package gcp_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/n24q02m/skret/internal/provider"
	skgcp "github.com/n24q02m/skret/internal/provider/gcp"
)

const (
	testProject  = "proj"
	testLocation = ""
	secretPrefix = "projects/" + testProject + "/secrets/"
)

// fakeGCP is an in-memory SecretManagerClient. Secret state lives in three
// maps keyed by fully-qualified resource names, mirroring the API's shape.
type fakeGCP struct {
	secrets  map[string]*secretmanagerpb.Secret // key: secret name
	versions map[string][]*secretmanagerpb.SecretVersion
	payloads map[string]string // key: version name

	errGetSecret       error
	errAccess          error
	errAccessForName   map[string]error // version name -> error
	nilPayload         bool             // return a response with a nil payload
	errAccessAfterAdds error            // readback error that only fires once an add was attempted
	errCreate          error
	errAdd             error
	errAddLostResponse bool // version commits but the response is lost (Unavailable)
	errUpdate          error
	errDelete          error
	errList            error
	errListVersions    error

	calls       []string
	createReqs  []*secretmanagerpb.CreateSecretRequest
	addReqs     []*secretmanagerpb.AddSecretVersionRequest
	updateReqs  []*secretmanagerpb.UpdateSecretRequest
	deleteReqs  []*secretmanagerpb.DeleteSecretRequest
	accessReqs  []*secretmanagerpb.AccessSecretVersionRequest
	listReqs    []*secretmanagerpb.ListSecretsRequest
	listVerReqs []*secretmanagerpb.ListSecretVersionsRequest
}

func newFakeGCP() *fakeGCP {
	return &fakeGCP{
		secrets:          map[string]*secretmanagerpb.Secret{},
		versions:         map[string][]*secretmanagerpb.SecretVersion{},
		payloads:         map[string]string{},
		errAccessForName: map[string]error{},
	}
}

// seed provisions a secret with n enabled versions (value = "v<N>") and an
// optional label/annotation set.
func (f *fakeGCP) seed(id string, n int, labels, annotations map[string]string, createAt *timestamppb.Timestamp) {
	name := secretPrefix + id
	f.secrets[name] = &secretmanagerpb.Secret{
		Name:        name,
		Labels:      labels,
		Annotations: annotations,
		CreateTime:  createAt,
	}
	f.seedVersions(id, n)
}

// seedVersions appends n enabled versions continuing the version sequence.
func (f *fakeGCP) seedVersions(id string, n int) {
	name := secretPrefix + id
	start := int64(len(f.versions[name]))
	for i := start + 1; i <= start+int64(n); i++ {
		vn := fmt.Sprintf("%s/versions/%d", name, i)
		f.versions[name] = append(f.versions[name], &secretmanagerpb.SecretVersion{
			Name:       vn,
			State:      secretmanagerpb.SecretVersion_ENABLED,
			CreateTime: timestamppb.New(time.Unix(0, 0).Add(time.Minute * time.Duration(i))),
		})
		f.payloads[vn] = "v" + strconv.FormatInt(i, 10)
	}
}

func newProvider(f *fakeGCP) provider.SecretProvider {
	return skgcp.NewWithClient(f, testProject, testLocation, "")
}

func (f *fakeGCP) GetSecret(_ context.Context, req *secretmanagerpb.GetSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	f.calls = append(f.calls, "GetSecret")
	if f.errGetSecret != nil {
		return nil, f.errGetSecret
	}
	s, ok := f.secrets[req.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return s, nil
}

func (f *fakeGCP) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.calls = append(f.calls, "AccessSecretVersion")
	f.accessReqs = append(f.accessReqs, req)
	if f.errAccess != nil {
		return nil, f.errAccess
	}
	if f.errAccessAfterAdds != nil && len(f.addReqs) > 0 {
		return nil, f.errAccessAfterAdds
	}
	if err, ok := f.errAccessForName[req.Name]; ok {
		return nil, err
	}
	name := req.Name
	if strings.HasSuffix(name, "/versions/latest") {
		parent := strings.TrimSuffix(name, "/versions/latest")
		versions := f.versions[parent]
		if len(versions) == 0 {
			return nil, status.Error(codes.NotFound, "no versions")
		}
		name = versions[len(versions)-1].Name // highest appended version
	}
	val, ok := f.payloads[name]
	if !ok {
		return nil, status.Error(codes.NotFound, "version not found")
	}
	if f.nilPayload {
		return &secretmanagerpb.AccessSecretVersionResponse{Name: name}, nil
	}
	return &secretmanagerpb.AccessSecretVersionResponse{Name: name, Payload: &secretmanagerpb.SecretPayload{Data: []byte(val)}}, nil
}

func (f *fakeGCP) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	f.calls = append(f.calls, "CreateSecret")
	f.createReqs = append(f.createReqs, req)
	if f.errCreate != nil {
		return nil, f.errCreate
	}
	name := req.Parent + "/secrets/" + req.SecretId
	if _, exists := f.secrets[name]; exists {
		return nil, status.Error(codes.AlreadyExists, "already exists")
	}
	f.secrets[name] = &secretmanagerpb.Secret{
		Name:        name,
		Labels:      req.Secret.GetLabels(),
		Annotations: req.Secret.GetAnnotations(),
		Replication: req.Secret.GetReplication(),
	}
	return f.secrets[name], nil
}

func (f *fakeGCP) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	f.calls = append(f.calls, "AddSecretVersion")
	f.addReqs = append(f.addReqs, req)
	if f.errAddLostResponse {
		f.commitVersion(req)
		return nil, status.Error(codes.Unavailable, "response lost after commit")
	}
	if f.errAdd != nil {
		return nil, f.errAdd
	}
	return f.commitVersion(req), nil
}

// commitVersion appends the next version for the secret and returns it.
func (f *fakeGCP) commitVersion(req *secretmanagerpb.AddSecretVersionRequest) *secretmanagerpb.SecretVersion {
	existing := f.versions[req.Parent]
	next := int64(len(existing) + 1)
	vn := fmt.Sprintf("%s/versions/%d", req.Parent, next)
	sv := &secretmanagerpb.SecretVersion{
		Name:       vn,
		State:      secretmanagerpb.SecretVersion_ENABLED,
		CreateTime: timestamppb.New(time.Unix(0, 0).Add(time.Minute * time.Duration(next+100))),
	}
	f.versions[req.Parent] = append(existing, sv)
	f.payloads[vn] = string(req.Payload.GetData())
	return sv
}

func (f *fakeGCP) UpdateSecret(_ context.Context, req *secretmanagerpb.UpdateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	f.calls = append(f.calls, "UpdateSecret")
	f.updateReqs = append(f.updateReqs, req)
	if f.errUpdate != nil {
		return nil, f.errUpdate
	}
	s, ok := f.secrets[req.Secret.Name]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	for _, path := range req.UpdateMask.GetPaths() {
		switch path {
		case "labels":
			s.Labels = req.Secret.Labels
		case "annotations":
			s.Annotations = req.Secret.Annotations
		}
	}
	return s, nil
}

func (f *fakeGCP) DeleteSecret(_ context.Context, req *secretmanagerpb.DeleteSecretRequest, _ ...gax.CallOption) error {
	f.calls = append(f.calls, "DeleteSecret")
	f.deleteReqs = append(f.deleteReqs, req)
	if f.errDelete != nil {
		return f.errDelete
	}
	if _, ok := f.secrets[req.Name]; !ok {
		return status.Error(codes.NotFound, "not found")
	}
	delete(f.secrets, req.Name)
	delete(f.versions, req.Name)
	return nil
}

func (f *fakeGCP) ListSecrets(_ context.Context, req *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) ([]*secretmanagerpb.Secret, error) {
	f.calls = append(f.calls, "ListSecrets")
	f.listReqs = append(f.listReqs, req)
	if f.errList != nil {
		return nil, f.errList
	}
	var out []*secretmanagerpb.Secret
	for _, s := range f.secrets {
		if req.Parent != "" && !hasParent(s.Name, req.Parent) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeGCP) ListSecretVersions(_ context.Context, req *secretmanagerpb.ListSecretVersionsRequest, _ ...gax.CallOption) ([]*secretmanagerpb.SecretVersion, error) {
	f.calls = append(f.calls, "ListSecretVersions")
	f.listVerReqs = append(f.listVerReqs, req)
	if f.errListVersions != nil {
		return nil, f.errListVersions
	}
	if _, ok := f.secrets[req.Parent]; !ok && len(f.versions[req.Parent]) == 0 {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return f.versions[req.Parent], nil
}

func hasParent(name, parent string) bool {
	return len(name) > len(parent) && name[:len(parent)] == parent && name[len(parent)] == '/'
}

func statusErr(c codes.Code) error { return status.Error(c, c.String()) }
