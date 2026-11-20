package gcp

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"path/filepath"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// stubClient is a SecretManagerClient whose behavior is set per test. Methods
// a test does not configure fall through to the nil embedded interface and
// panic, so an unexpected call fails loudly.
type stubClient struct {
	SecretManagerClient

	getSecret    func(name string) (*secretmanagerpb.Secret, error)
	access       func(name string) (*secretmanagerpb.AccessSecretVersionResponse, error)
	listSecrets  func() ([]*secretmanagerpb.Secret, error)
	listVersions func(parent string) ([]*secretmanagerpb.SecretVersion, error)
}

func (s *stubClient) GetSecret(_ context.Context, req *secretmanagerpb.GetSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return s.getSecret(req.GetName())
}

func (s *stubClient) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return s.access(req.GetName())
}

func (s *stubClient) ListSecrets(_ context.Context, _ *secretmanagerpb.ListSecretsRequest, _ ...gax.CallOption) ([]*secretmanagerpb.Secret, error) {
	return s.listSecrets()
}

func (s *stubClient) ListSecretVersions(_ context.Context, req *secretmanagerpb.ListSecretVersionsRequest, _ ...gax.CallOption) ([]*secretmanagerpb.SecretVersion, error) {
	return s.listVersions(req.GetParent())
}

func denied(string) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "caller lacks secretAccessor")
}

func stubProvider(c *stubClient) *Provider {
	return &Provider{client: c, project: "proj"}
}

// deniedListServer is a Secret Manager gRPC server that rejects both listings,
// so the real generated iterators surface a server error mid-drain.
type deniedListServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (deniedListServer) ListSecrets(context.Context, *secretmanagerpb.ListSecretsRequest) (*secretmanagerpb.ListSecretsResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "list denied")
}

func (deniedListServer) ListSecretVersions(context.Context, *secretmanagerpb.ListSecretVersionsRequest) (*secretmanagerpb.ListSecretVersionsResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "list versions denied")
}

// bufconnOption serves srv over an in-memory listener and returns the client
// option that points the generated client at it.
func bufconnOption(t *testing.T, srv secretmanagerpb.SecretManagerServiceServer) option.ClientOption {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return option.WithGRPCConn(conn)
}

// New surfaces the dial failure unchanged and returns no provider.
func TestNewReturnsDialError(t *testing.T) {
	orig := dialSecretManager
	t.Cleanup(func() { dialSecretManager = orig })
	dialErr := errors.New("dial refused")
	dialSecretManager = func(context.Context, string) (SecretManagerClient, error) { return nil, dialErr }

	p, err := New(&config.ResolvedConfig{Provider: "gcp", Project: "proj"})
	assert.Nil(t, p)
	assert.ErrorIs(t, err, dialErr)
}

// The real client constructor fails before any dial when the ADC file named
// by GOOGLE_APPLICATION_CREDENTIALS is missing, for both the global and a
// regional endpoint, and the cause stays inspectable under the gcp envelope.
func TestNewGRPCClientReportsBrokenADC(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-adc.json"))

	for _, location := range []string{"", "us-east1"} {
		client, err := newGRPCClient(context.Background(), location)
		assert.Nil(t, client, "location %q", location)
		require.Error(t, err, "location %q", location)
		assert.Contains(t, err.Error(), "gcp: create secret manager client: ", "location %q", location)
		assert.ErrorIs(t, err, fs.ErrNotExist, "location %q", location)
	}
}

// With an explicit connection the constructor returns a working adapter: a
// listing error from the server reaches the provider as a mapped error that
// keeps the gRPC status.
func TestGRPCAdapterSurfacesListErrors(t *testing.T) {
	client, err := newGRPCClientWithOpts(context.Background(), bufconnOption(t, deniedListServer{}))
	require.NoError(t, err)
	p := NewWithClient(client, "proj", "", "")
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: list ""`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))

	_, err = p.GetHistory(context.Background(), "KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: history "KEY"`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
}

// Probe reports a failed bounded listing under the probe envelope.
func TestProbeReportsListError(t *testing.T) {
	orig := dialSecretManager
	t.Cleanup(func() { dialSecretManager = orig })
	dialSecretManager = func(context.Context, string) (SecretManagerClient, error) {
		return &stubClient{listSecrets: func() ([]*secretmanagerpb.Secret, error) {
			return nil, status.Error(codes.PermissionDenied, "probe denied")
		}}, nil
	}

	err := Probe(context.Background(), &config.ResolvedConfig{Provider: "gcp", Project: "proj"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: probe ""`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
}

// Keys that cannot be GCP secret ids are rejected before any API call by
// GetVersion and GetHistory (and therefore Rollback).
func TestInvalidKeysRejectedBeforeAPICalls(t *testing.T) {
	p := stubProvider(&stubClient{})

	_, err := p.GetVersion(context.Background(), "a/b", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: get_version "a/b": invalid secret id`)

	_, err = p.GetHistory(context.Background(), "a/b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: history "a/b": invalid secret id`)

	err = p.Rollback(context.Background(), "a/b", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: history "a/b": invalid secret id`)
}

// GetVersion treats a response for a different version than requested as a
// miss rather than returning the wrong value.
func TestGetVersionRejectsMismatchedVersion(t *testing.T) {
	p := stubProvider(&stubClient{access: func(string) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Name:    "projects/proj/secrets/KEY/versions/3",
			Payload: &secretmanagerpb.SecretPayload{Data: []byte("v3")},
		}, nil
	}})

	_, err := p.GetVersion(context.Background(), "KEY", 2)
	assert.ErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `gcp: get_version "KEY"`)
}

// List skips secrets without a readable version but fails the listing on
// any other access error, naming the secret that failed.
func TestListFailsOnNonNotFoundAccessError(t *testing.T) {
	p := stubProvider(&stubClient{
		listSecrets: func() ([]*secretmanagerpb.Secret, error) {
			return []*secretmanagerpb.Secret{{Name: "projects/proj/secrets/LOCKED"}}, nil
		},
		access: denied,
	})

	_, err := p.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: list "LOCKED"`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
}

// Set stops before writing when the existence check or the pre-write version
// read fails with anything other than NotFound.
func TestSetStopsOnPreWriteReadErrors(t *testing.T) {
	getDenied := stubProvider(&stubClient{getSecret: func(string) (*secretmanagerpb.Secret, error) {
		return nil, status.Error(codes.PermissionDenied, "get denied")
	}})
	err := getDenied.Set(context.Background(), "KEY", "fixture-secret-value", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: set "KEY"`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
	assert.NotContains(t, err.Error(), "fixture-secret-value")

	accessDenied := stubProvider(&stubClient{
		getSecret: func(name string) (*secretmanagerpb.Secret, error) {
			return &secretmanagerpb.Secret{Name: name}, nil
		},
		access: denied,
	})
	err = accessDenied.Set(context.Background(), "KEY", "fixture-secret-value", provider.SecretMeta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: set "KEY"`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
	assert.NotContains(t, err.Error(), "fixture-secret-value")
}

// GetHistory drops versions destroyed between listing and reading, but fails
// on any other access error; Rollback passes that failure through.
func TestHistoryFailsOnNonNotFoundAccessError(t *testing.T) {
	p := stubProvider(&stubClient{
		listVersions: func(parent string) ([]*secretmanagerpb.SecretVersion, error) {
			return []*secretmanagerpb.SecretVersion{{
				Name:  parent + "/versions/1",
				State: secretmanagerpb.SecretVersion_ENABLED,
			}}, nil
		},
		access: denied,
	})

	_, err := p.GetHistory(context.Background(), "KEY")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `gcp: history "KEY"`)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))

	err = p.Rollback(context.Background(), "KEY", 1)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
}
