package gcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeServer is an in-process Secret Manager gRPC server driving the REAL
// generated client (protobuf marshal, iterators, page tokens) through the
// grpcClient adapter — the transport-layer coverage the interface fakes in
// gcp_test.go cannot reach.
type fakeServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	secrets   map[string]*secretmanagerpb.Secret
	versions  map[string][]*secretmanagerpb.SecretVersion
	payloads  map[string]string
	pageSize  int32 // small to force multi-page listings
	createErr error
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		secrets:  map[string]*secretmanagerpb.Secret{},
		versions: map[string][]*secretmanagerpb.SecretVersion{},
		payloads: map[string]string{},
		pageSize: 1,
	}
}

func (s *fakeServer) seed(project, id string, n int) {
	name := fmt.Sprintf("projects/%s/secrets/%s", project, id)
	s.secrets[name] = &secretmanagerpb.Secret{Name: name, CreateTime: timestamppb.Now()}
	for i := 1; i <= n; i++ {
		vn := fmt.Sprintf("%s/versions/%d", name, i)
		s.versions[name] = append(s.versions[name], &secretmanagerpb.SecretVersion{
			Name:  vn,
			State: secretmanagerpb.SecretVersion_ENABLED,
		})
		s.payloads[vn] = "v" + strconv.Itoa(i)
	}
}

func pageOf[T any](items []T, token string, size int32) ([]T, string) {
	offset := 0
	if token != "" {
		offset, _ = strconv.Atoi(token)
	}
	end := offset + int(size)
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return items[offset:end], next
}

func (s *fakeServer) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest) (*secretmanagerpb.ListSecretsResponse, error) {
	var all []*secretmanagerpb.Secret
	for _, sec := range s.secrets {
		all = append(all, sec)
	}
	page, next := pageOf(all, req.PageToken, s.pageSize)
	return &secretmanagerpb.ListSecretsResponse{Secrets: page, NextPageToken: next}, nil
}

func (s *fakeServer) ListSecretVersions(ctx context.Context, req *secretmanagerpb.ListSecretVersionsRequest) (*secretmanagerpb.ListSecretVersionsResponse, error) {
	versions := s.versions[req.Parent]
	page, next := pageOf(versions, req.PageToken, s.pageSize)
	return &secretmanagerpb.ListSecretVersionsResponse{Versions: page, NextPageToken: next}, nil
}

func (s *fakeServer) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	name := req.Name
	if val, ok := s.payloads[name]; ok {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Name:    name,
			Payload: &secretmanagerpb.SecretPayload{Data: []byte(val)},
		}, nil
	}
	if stringsHasSuffixLatest(name) {
		parent := name[:len(name)-len("/versions/latest")]
		if versions := s.versions[parent]; len(versions) > 0 {
			latest := versions[len(versions)-1]
			return &secretmanagerpb.AccessSecretVersionResponse{
				Name:    latest.Name,
				Payload: &secretmanagerpb.SecretPayload{Data: []byte(s.payloads[latest.Name])},
			}, nil
		}
	}
	return nil, statusNotFound()
}

func stringsHasSuffixLatest(name string) bool {
	const suffix = "/versions/latest"
	return len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix
}

func (s *fakeServer) GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest) (*secretmanagerpb.Secret, error) {
	if sec, ok := s.secrets[req.Name]; ok {
		return sec, nil
	}
	return nil, statusNotFound()
}

func (s *fakeServer) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	name := req.Parent + "/secrets/" + req.SecretId
	sec := &secretmanagerpb.Secret{
		Name:        name,
		Labels:      req.Secret.GetLabels(),
		Annotations: req.Secret.GetAnnotations(),
		Replication: req.Secret.GetReplication(),
	}
	s.secrets[name] = sec
	return sec, nil
}

func (s *fakeServer) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	next := int64(len(s.versions[req.Parent]) + 1)
	vn := fmt.Sprintf("%s/versions/%d", req.Parent, next)
	sv := &secretmanagerpb.SecretVersion{Name: vn, State: secretmanagerpb.SecretVersion_ENABLED}
	s.versions[req.Parent] = append(s.versions[req.Parent], sv)
	s.payloads[vn] = string(req.Payload.GetData())
	return sv, nil
}

func (s *fakeServer) UpdateSecret(ctx context.Context, req *secretmanagerpb.UpdateSecretRequest) (*secretmanagerpb.Secret, error) {
	sec, ok := s.secrets[req.Secret.Name]
	if !ok {
		return nil, statusNotFound()
	}
	for _, path := range req.UpdateMask.GetPaths() {
		switch path {
		case "labels":
			sec.Labels = req.Secret.Labels
		case "annotations":
			sec.Annotations = req.Secret.Annotations
		}
	}
	return sec, nil
}

func (s *fakeServer) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest) (*emptypb.Empty, error) {
	if _, ok := s.secrets[req.Name]; !ok {
		return nil, statusNotFound()
	}
	delete(s.secrets, req.Name)
	delete(s.versions, req.Name)
	return &emptypb.Empty{}, nil
}

func statusNotFound() error { return status.Error(codes.NotFound, "not found") }

// newBufconnProvider wires the real generated client to a fakeServer over an
// in-memory listener (no ADC, no network).
func newBufconnProvider(t *testing.T, project string) (provider.SecretProvider, *fakeServer) {
	t.Helper()
	srv := newFakeServer()
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client, err := secretmanager.NewClient(context.Background(), option.WithGRPCConn(conn))
	require.NoError(t, err, "WithGRPCConn must bypass ADC resolution")
	t.Cleanup(func() { _ = client.Close() })

	p := NewWithClient(&grpcClient{client: client}, project, "", "")
	return p, srv
}

func TestGRPCStackEndToEnd(t *testing.T) {
	ctx := context.Background()
	p, srv := newBufconnProvider(t, "e2e-proj")
	srv.seed("e2e-proj", "EXISTING", 2)

	t.Run("get latest through real client", func(t *testing.T) {
		s, err := p.Get(ctx, "EXISTING")
		require.NoError(t, err)
		assert.Equal(t, "v2", s.Value)
		assert.Equal(t, int64(2), s.Version)
	})

	t.Run("list drains multiple server pages", func(t *testing.T) {
		secrets, err := p.List(ctx, "")
		require.NoError(t, err)
		require.Len(t, secrets, 1)
		assert.Equal(t, "EXISTING", secrets[0].Key)
	})

	t.Run("fingerprint over real iterators", func(t *testing.T) {
		fp, err := p.Fingerprint(ctx, "")
		require.NoError(t, err)
		assert.NotEmpty(t, fp)
	})

	t.Run("set then rollback through the stack", func(t *testing.T) {
		require.NoError(t, p.Set(ctx, "NEW_KEY", "fresh", provider.SecretMeta{Description: "made by test"}))

		s, err := p.Get(ctx, "NEW_KEY")
		require.NoError(t, err)
		assert.Equal(t, "fresh", s.Value)

		require.NoError(t, p.Set(ctx, "NEW_KEY", "second", provider.SecretMeta{}))
		require.NoError(t, p.Rollback(ctx, "NEW_KEY", 1))

		s, err = p.Get(ctx, "NEW_KEY")
		require.NoError(t, err)
		assert.Equal(t, "fresh", s.Value, "rollback must restore version 1's value")

		history, err := p.GetHistory(ctx, "NEW_KEY")
		require.NoError(t, err)
		assert.Len(t, history, 3)

		require.NoError(t, p.Delete(ctx, "NEW_KEY"))
		_, err = p.Get(ctx, "NEW_KEY")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("regional resource names", func(t *testing.T) {
		srvRegion := newFakeServer()
		srvRegion.seedRegional("reg-proj", "us-east1", "K", 1)
		rp, _ := rebindProvider(t, "reg-proj", "us-east1", srvRegion)
		s, err := rp.Get(ctx, "K")
		require.NoError(t, err)
		assert.Equal(t, "v1", s.Value)
	})
}

func rebindProvider(t *testing.T, project, location string, srv *fakeServer) (provider.SecretProvider, *fakeServer) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client, err := secretmanager.NewClient(context.Background(), option.WithGRPCConn(conn))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return NewWithClient(&grpcClient{client: client}, project, location, ""), srv
}

// seedRegional seeds a location-qualified secret.
func (s *fakeServer) seedRegional(project, location, id string, n int) {
	name := fmt.Sprintf("projects/%s/locations/%s/secrets/%s", project, location, id)
	s.secrets[name] = &secretmanagerpb.Secret{Name: name}
	for i := 1; i <= n; i++ {
		vn := fmt.Sprintf("%s/versions/%d", name, i)
		s.versions[name] = append(s.versions[name], &secretmanagerpb.SecretVersion{
			Name:  vn,
			State: secretmanagerpb.SecretVersion_ENABLED,
		})
		s.payloads[vn] = "v" + strconv.Itoa(i)
	}
}

func TestNewRequiresProject(t *testing.T) {
	_, err := New(&config.ResolvedConfig{Provider: "gcp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project is required")

	_, err = New(nil)
	require.Error(t, err)
}

func TestNewThroughDialSeam(t *testing.T) {
	orig := dialSecretManager
	t.Cleanup(func() { dialSecretManager = orig })

	var dialedLocation string
	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	srv := newFakeServer()
	srv.seedRegional("hook-proj", "us-east1", "K", 1)
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	dialSecretManager = func(ctx context.Context, location string) (SecretManagerClient, error) {
		dialedLocation = location
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		client, err := secretmanager.NewClient(context.Background(), option.WithGRPCConn(conn))
		require.NoError(t, err)
		return &grpcClient{client: client}, nil
	}

	p, err := New(&config.ResolvedConfig{Provider: "gcp", Project: "hook-proj", Region: "us-east1", KMSKeyID: "cmek"})
	require.NoError(t, err)
	assert.Equal(t, "us-east1", dialedLocation, "New must forward the region as the GCP location")
	s, err := p.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "v1", s.Value)
	require.NoError(t, p.Close())
}

func TestProbeThroughDialSeam(t *testing.T) {
	orig := dialSecretManager
	t.Cleanup(func() { dialSecretManager = orig })

	listener := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	srv := newFakeServer()
	srv.seed("probe-proj", "K", 1)
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	dialSecretManager = func(ctx context.Context, location string) (SecretManagerClient, error) {
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		client, err := secretmanager.NewClient(context.Background(), option.WithGRPCConn(conn))
		require.NoError(t, err)
		return &grpcClient{client: client}, nil
	}

	require.NoError(t, Probe(context.Background(), &config.ResolvedConfig{Provider: "gcp", Project: "probe-proj"}))
	require.Error(t, Probe(context.Background(), &config.ResolvedConfig{Provider: "gcp"}),
		"probe without a project must fail before dialing")

	dialSecretManager = func(ctx context.Context, location string) (SecretManagerClient, error) {
		return nil, wrapClientError(errors.New("could not find default credentials"))
	}
	err := Probe(context.Background(), &config.ResolvedConfig{Provider: "gcp", Project: "probe-proj"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Google Cloud credentials found")
	assert.Contains(t, err.Error(), "GOOGLE_APPLICATION_CREDENTIALS")
}

func TestWrapClientError(t *testing.T) {
	err := wrapClientError(errors.New("could not find default credentials"))
	assert.Contains(t, err.Error(), "no Google Cloud credentials found")
	assert.Contains(t, err.Error(), "workload identity")

	plain := wrapClientError(errors.New("boom"))
	assert.Contains(t, plain.Error(), "gcp: create secret manager client")
}

func TestAdapterListEmptyProject(t *testing.T) {
	p, _ := newBufconnProvider(t, "empty-proj")
	secrets, err := p.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, secrets, "no secrets seeded means an empty listing")
}
