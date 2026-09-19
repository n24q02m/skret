package gcp

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/n24q02m/skret/internal/config"
)

// regionalEndpoint returns the Secret Manager regional service endpoint for
// a location (e.g. "secretmanager.us-east1.rep.googleapis.com:443"). The
// global endpoint is the client default, so an empty location needs no
// override.
func regionalEndpoint(location string) string {
	return fmt.Sprintf("secretmanager.%s.rep.googleapis.com:443", location)
}

// dialSecretManager builds the real Secret Manager client. A package var so
// tests inject a bufconn-backed client instead of resolving ADC.
var dialSecretManager = newGRPCClient

// newGRPCClient builds the real Secret Manager client on Application Default
// Credentials. Missing ADC is the overwhelmingly likely failure and gets an
// actionable message; anything else passes through wrapped.
func newGRPCClient(ctx context.Context, location string) (SecretManagerClient, error) {
	var opts []option.ClientOption
	if location != "" {
		opts = append(opts, option.WithEndpoint(regionalEndpoint(location)))
	}
	return newGRPCClientWithOpts(ctx, opts...)
}

func newGRPCClientWithOpts(ctx context.Context, opts ...option.ClientOption) (SecretManagerClient, error) {
	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, wrapClientError(err)
	}
	return &grpcClient{client: client}, nil
}

// wrapClientError annotates client-construction failures. Missing ADC gets
// the three standard remedies spelled out.
func wrapClientError(err error) error {
	if strings.Contains(strings.ToLower(err.Error()), "default credentials") {
		return fmt.Errorf(
			"gcp: no Google Cloud credentials found: set GOOGLE_APPLICATION_CREDENTIALS, run 'gcloud auth application-default login', or use workload identity on GCP infrastructure: %w", err)
	}
	return fmt.Errorf("gcp: create secret manager client: %w", err)
}

// grpcClient adapts the generated Secret Manager client to the
// SecretManagerClient seam, draining list iterators into plain slices.
type grpcClient struct {
	client *secretmanager.Client
}

func (g *grpcClient) GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return g.client.GetSecret(ctx, req, opts...)
}

func (g *grpcClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return g.client.AccessSecretVersion(ctx, req, opts...)
}

func (g *grpcClient) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return g.client.CreateSecret(ctx, req, opts...)
}

func (g *grpcClient) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return g.client.AddSecretVersion(ctx, req, opts...)
}

func (g *grpcClient) UpdateSecret(ctx context.Context, req *secretmanagerpb.UpdateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return g.client.UpdateSecret(ctx, req, opts...)
}

func (g *grpcClient) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
	return g.client.DeleteSecret(ctx, req, opts...)
}

func (g *grpcClient) ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) ([]*secretmanagerpb.Secret, error) {
	it := g.client.ListSecrets(ctx, req, opts...)
	var out []*secretmanagerpb.Secret
	for {
		s, err := it.Next()
		if err == iterator.Done {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
}

func (g *grpcClient) ListSecretVersions(ctx context.Context, req *secretmanagerpb.ListSecretVersionsRequest, opts ...gax.CallOption) ([]*secretmanagerpb.SecretVersion, error) {
	it := g.client.ListSecretVersions(ctx, req, opts...)
	var out []*secretmanagerpb.SecretVersion
	for {
		v, err := it.Next()
		if err == iterator.Done {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

// Close releases the underlying gRPC connection.
func (g *grpcClient) Close() error { return g.client.Close() }

// Probe verifies that Application Default Credentials resolve and that the
// Secret Manager API answers, with one bounded 1-result listing. It never
// reads a secret value. Used by `skret doctor`.
func Probe(ctx context.Context, cfg *config.ResolvedConfig) error {
	p, err := newConcrete(ctx, cfg)
	if err != nil {
		return err
	}
	_, err = p.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: p.parent(), PageSize: 1})
	cerr := p.Close()
	if err != nil {
		return mapError("probe", "", err)
	}
	return cerr
}

// newConcrete builds a concrete provider; New returns the interface type, so
// the doctor probe constructs the struct directly to reach parent().
func newConcrete(ctx context.Context, cfg *config.ResolvedConfig) (*Provider, error) {
	if cfg == nil || cfg.Project == "" {
		return nil, fmt.Errorf("gcp: project is required (set `project` on the environment or GOOGLE_CLOUD_PROJECT)")
	}
	client, err := dialSecretManager(ctx, cfg.Region)
	if err != nil {
		return nil, err
	}
	return &Provider{
		client:   client,
		project:  cfg.Project,
		location: cfg.Region,
		kmsKeyID: cfg.KMSKeyID,
	}, nil
}
