// Package gcp implements the SecretProvider contract against Google Cloud
// Secret Manager.
//
// GCP secret IDs are FLAT: unlike AWS SSM paths there is no hierarchy, and
// IDs may contain only alphanumerics, dashes and underscores. skret keys are
// therefore used verbatim as secret IDs (a single leading "/" is tolerated
// and stripped so muscle memory from the aws provider does not bite). The
// environment's `path` must stay empty; isolation comes from one GCP project
// per environment.
package gcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// maxPayloadBytes is Secret Manager's per-version payload cap (64 KiB).
// Checking it locally keeps the error message actionable instead of leaking
// a gRPC InvalidArgument.
const maxPayloadBytes = 64 * 1024

// secretIDPattern is GCP's secret-id rule: 1-255 chars, alphanumerics,
// dashes and underscores.
var secretIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,255}$`)

// Reserved annotations mirroring SecretMeta into GCP-native metadata. GCP has
// no description field (annotations are the documented stand-in) and no
// resource tags (labels are the documented stand-in).
const (
	AnnotationDescription = "skret-description"
	AnnotationExpiresAt   = "skret-expires-at"
)

// SecretManagerClient abstracts the Secret Manager API for testability. The
// list methods return drained pages so implementations (and test fakes) do
// not need to model iterator state.
type SecretManagerClient interface {
	GetSecret(ctx context.Context, req *secretmanagerpb.GetSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	UpdateSecret(ctx context.Context, req *secretmanagerpb.UpdateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) ([]*secretmanagerpb.Secret, error)
	ListSecretVersions(ctx context.Context, req *secretmanagerpb.ListSecretVersionsRequest, opts ...gax.CallOption) ([]*secretmanagerpb.SecretVersion, error)
}

// Provider wraps GCP Secret Manager.
type Provider struct {
	client   SecretManagerClient
	project  string
	location string // empty for the global endpoint
	kmsKeyID string // optional CMEK key for new secrets
}

// New creates a GCP Secret Manager provider from resolved config.
//
// Authentication uses Application Default Credentials exclusively: the
// GOOGLE_APPLICATION_CREDENTIALS env var, `gcloud auth application-default
// login`, or workload identity when running on GCP infrastructure. skret
// stores no GCP credential of its own.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	if cfg == nil || cfg.Project == "" {
		return nil, fmt.Errorf("gcp: project is required (set `project` on the environment or GOOGLE_CLOUD_PROJECT)")
	}
	client, err := dialSecretManager(context.Background(), cfg.Region)
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

// NewWithClient creates a provider with a custom Secret Manager client (for
// testing).
func NewWithClient(client SecretManagerClient, project, location, kmsKeyID string) provider.SecretProvider {
	return &Provider{client: client, project: project, location: location, kmsKeyID: kmsKeyID}
}

func (p *Provider) Name() string { return "gcp" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		Write:      true,
		Versioning: true,
		Tagging:    true,
		AuditLog:   true,
		MaxValueKB: 64,
	}
}

// parent is the collection prefix for List calls:
// projects/{p}[/locations/{l}].
func (p *Provider) parent() string {
	if p.location != "" {
		return "projects/" + p.project + "/locations/" + p.location
	}
	return "projects/" + p.project
}

// secretPath is the fully-qualified secret resource name.
func (p *Provider) secretPath(id string) string {
	return p.parent() + "/secrets/" + id
}

// secretID validates a skret key and returns the GCP secret id. Keys are
// flat; anything a GCP secret id cannot hold is rejected with an actionable
// error rather than silently rewritten.
func secretID(op, key string) (string, error) {
	id := strings.TrimPrefix(key, "/")
	if !secretIDPattern.MatchString(id) {
		return "", fmt.Errorf(
			"gcp: %s %q: invalid secret id %q: GCP secret ids must be 1-255 chars of [a-zA-Z0-9_-] with no path separators; gcp environments keep `path` empty and use one project per environment",
			op, key, id)
	}
	return id, nil
}

func (p *Provider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	if p == nil || p.client == nil || key == "" {
		return nil, provider.ErrNotFound
	}
	id, err := secretID("get", key)
	if err != nil {
		return nil, err
	}
	secret, err := p.accessVersionRaw(ctx, p.secretPath(id)+"/versions/latest")
	if err != nil {
		return nil, mapError("get", key, err)
	}
	secret.Key = id
	return secret, nil
}

// accessVersionRaw reads one version resource name and maps it to a Secret,
// returning the RAW API error so classification helpers (isNotFound, ...)
// still see the gRPC status. Mapping to the skret envelope happens at the
// public-method boundary.
func (p *Provider) accessVersionRaw(ctx context.Context, versionName string) (*provider.Secret, error) {
	resp, err := p.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: versionName})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Payload == nil {
		return nil, status.Error(codes.NotFound, "empty access response")
	}
	return &provider.Secret{
		Value:   string(resp.Payload.Data),
		Version: versionNumberOf(resp.GetName()),
	}, nil
}

// versionNumberOf parses the trailing version number off a
// .../versions/{n} resource name. 0 means "unknown" (unparseable).
func versionNumberOf(versionName string) int64 {
	idx := strings.LastIndex(versionName, "/versions/")
	if idx < 0 {
		return 0
	}
	v, err := strconv.ParseInt(versionName[idx+len("/versions/"):], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// GetVersion reads one immutable secret version.
func (p *Provider) GetVersion(ctx context.Context, key string, version int64) (*provider.Secret, error) {
	if p == nil || p.client == nil || key == "" || version <= 0 {
		return nil, provider.ErrNotFound
	}
	id, err := secretID("get_version", key)
	if err != nil {
		return nil, err
	}
	secret, err := p.accessVersionRaw(ctx, fmt.Sprintf("%s/versions/%d", p.secretPath(id), version))
	if err != nil {
		return nil, mapError("get_version", key, err)
	}
	if secret.Version != version {
		return nil, mapError("get_version", key, status.Error(codes.NotFound, "version mismatch"))
	}
	secret.Key = id
	return secret, nil
}

func (p *Provider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	// Secret Manager has no batch-read API; read sequentially in input
	// order. Missing keys are skipped silently, matching the aws provider's
	// GetParameters behavior (missing names land in InvalidParameters and
	// are dropped).
	allSecrets := make([]*provider.Secret, 0, len(keys))
	for _, key := range keys {
		s, err := p.Get(ctx, key)
		if err != nil {
			if errors.Is(err, provider.ErrNotFound) {
				continue
			}
			return nil, err
		}
		allSecrets = append(allSecrets, s)
	}
	return allSecrets, nil
}

// listPrefix normalizes a List prefix: GCP ids are flat, so the prefix is a
// plain string match on the secret id (leading "/" tolerated).
func listPrefix(pathPrefix string) string {
	return strings.TrimPrefix(pathPrefix, "/")
}

func (p *Provider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	prefix := listPrefix(pathPrefix)
	secrets, err := p.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: p.parent()})
	if err != nil {
		return nil, mapError("list", pathPrefix, err)
	}
	var out []*provider.Secret
	for _, s := range secrets {
		id := secretNameID(s.GetName())
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		secret, err := p.accessVersionRaw(ctx, s.GetName()+"/versions/latest")
		if err != nil {
			// A secret with zero (or no enabled) versions has no readable
			// value; skip it like the aws provider drops missing batch
			// names, instead of failing the whole listing.
			if isNotFound(err) {
				continue
			}
			return nil, mapError("list", id, err)
		}
		secret.Key = id
		out = append(out, secret)
		if s.CreateTime != nil {
			out[len(out)-1].Meta.CreatedAt = s.CreateTime.AsTime()
		}
	}
	return out, nil
}

func (p *Provider) ListNames(ctx context.Context, pathPrefix string) ([]string, error) {
	prefix := listPrefix(pathPrefix)
	secrets, err := p.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: p.parent()})
	if err != nil {
		return nil, mapError("list", pathPrefix, err)
	}
	var names []string
	for _, s := range secrets {
		id := secretNameID(s.GetName())
		if prefix == "" || strings.HasPrefix(id, prefix) {
			names = append(names, id)
		}
	}
	return names, nil
}

// secretNameID extracts the bare secret id from a fully-qualified
// projects/x/secrets/{id} resource name.
func secretNameID(name string) string {
	idx := strings.LastIndex(name, "/secrets/")
	if idx < 0 {
		return name
	}
	return name[idx+len("/secrets/"):]
}

// Fingerprint hashes the secret set WITHOUT decrypting any value: one line
// per secret carrying the highest enabled version number. Used by
// `run --watch` so polling costs zero decryption calls.
func (p *Provider) Fingerprint(ctx context.Context, pathPrefix string) (string, error) {
	prefix := listPrefix(pathPrefix)
	secrets, err := p.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: p.parent()})
	if err != nil {
		return "", mapError("fingerprint", pathPrefix, err)
	}
	var lines []string
	for _, s := range secrets {
		id := secretNameID(s.GetName())
		if prefix != "" && !strings.HasPrefix(id, prefix) {
			continue
		}
		versions, err := p.client.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{Parent: s.GetName()})
		if err != nil {
			return "", mapError("fingerprint", id, err)
		}
		lines = append(lines, fmt.Sprintf("%s@%d", id, highestEnabledVersion(versions)))
	}
	return hashLines(lines), nil
}

// highestEnabledVersion returns the largest ENABLED version number; 0 when
// the secret has no enabled versions.
func highestEnabledVersion(versions []*secretmanagerpb.SecretVersion) int64 {
	var highest int64
	for _, v := range versions {
		if v.GetState() != secretmanagerpb.SecretVersion_ENABLED {
			continue
		}
		if n := versionNumberOf(v.GetName()); n > highest {
			highest = n
		}
	}
	return highest
}

// hashLines returns a stable sha256 hex digest of lines, independent of order.
func hashLines(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(joined)))
}

// annotationsFromMeta renders SecretMeta as GCP annotations. A non-zero
// ExpiresAt is mirrored to AnnotationExpiresAt and wins over a user-supplied
// annotation of the same name (the timestamp is the authoritative source).
func annotationsFromMeta(meta provider.SecretMeta) map[string]string {
	out := map[string]string{}
	if meta.Description != "" {
		out[AnnotationDescription] = meta.Description
	}
	if !meta.ExpiresAt.IsZero() {
		out[AnnotationExpiresAt] = meta.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return out
}

func equalStringMaps(want, have map[string]string) bool {
	if len(want) != len(have) {
		return false
	}
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// fieldMask builds an update mask over top-level Secret fields.
func fieldMask(paths ...string) *fieldmaskpb.FieldMask {
	return &fieldmaskpb.FieldMask{Paths: paths}
}

// replicationFromMeta builds the replication policy for a new secret: a CMEK
// key rides automatic replication globally and user-managed replication when
// a location is configured.
func (p *Provider) replication() *secretmanagerpb.Replication {
	cmek := func() *secretmanagerpb.CustomerManagedEncryption {
		if p.kmsKeyID == "" {
			return nil
		}
		return &secretmanagerpb.CustomerManagedEncryption{KmsKeyName: p.kmsKeyID}
	}
	if p.location != "" {
		return &secretmanagerpb.Replication{
			Replication: &secretmanagerpb.Replication_UserManaged_{
				UserManaged: &secretmanagerpb.Replication_UserManaged{
					Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
						{Location: p.location, CustomerManagedEncryption: cmek()},
					},
				},
			},
		}
	}
	return &secretmanagerpb.Replication{
		Replication: &secretmanagerpb.Replication_Automatic_{
			Automatic: &secretmanagerpb.Replication_Automatic{CustomerManagedEncryption: cmek()},
		},
	}
}

// labelsFromMeta copies user tags as GCP labels. Label keys/values must
// satisfy GCP's label rules (lowercase [a-z0-9_-], <=63 bytes); violations
// surface as the API's InvalidArgument mapped through mapError.
func labelsFromMeta(meta provider.SecretMeta) map[string]string {
	if len(meta.Tags) == 0 {
		return nil
	}
	labels := make(map[string]string, len(meta.Tags))
	for k, v := range meta.Tags {
		labels[k] = v
	}
	return labels
}

func (p *Provider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	if len(value) > maxPayloadBytes {
		return fmt.Errorf("gcp: set %q: value is %d bytes, GCP Secret Manager caps payloads at %d bytes", key, len(value), maxPayloadBytes)
	}
	id, err := secretID("set", key)
	if err != nil {
		return err
	}
	name := p.secretPath(id)

	existing, err := p.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: name})
	if err != nil && !isNotFound(err) {
		return mapError("set", key, err)
	}

	// Track the pre-write latest version so an ambiguous transport failure
	// can be reconciled into a definite outcome (committed or not).
	preVersion := int64(0)
	if existing != nil {
		pre, err := p.latestVersion(ctx, name)
		if err != nil {
			return mapError("set", key, err)
		}
		preVersion = pre
	}

	wantAnnotations := annotationsFromMeta(meta)
	wantLabels := labelsFromMeta(meta)

	if existing == nil {
		if _, err := p.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   p.parent(),
			SecretId: id,
			Secret: &secretmanagerpb.Secret{
				Labels:      wantLabels,
				Annotations: wantAnnotations,
				Replication: p.replication(),
			},
		}); err != nil {
			// Ambiguous create failures reconcile exactly like failed adds:
			// with no pre-write version there is nothing to compare, so the
			// readback decides between "nothing happened" and unknown.
			return p.reconcileSetFailure(ctx, key, name, preVersion, err)
		}
	}

	added, err := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  name,
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
	})
	if err != nil {
		return p.reconcileSetFailure(ctx, key, name, preVersion, err)
	}
	committedVersion := int64(0)
	if added != nil {
		committedVersion = versionNumberOf(added.GetName())
	}

	if existing != nil && (!equalStringMaps(wantAnnotations, existing.GetAnnotations()) || !equalStringMaps(wantLabels, existing.GetLabels())) {
		if _, err := p.client.UpdateSecret(ctx, &secretmanagerpb.UpdateSecretRequest{
			Secret: &secretmanagerpb.Secret{
				Name:        name,
				Labels:      wantLabels,
				Annotations: wantAnnotations,
			},
			UpdateMask: fieldMask("labels", "annotations"),
		}); err != nil {
			// The value committed; only the mirrored metadata is stale.
			return &provider.PartialCommitError{
				Provider:        p.Name(),
				Key:             key,
				Version:         committedVersion,
				ObservedVersion: committedVersion,
				TagState:        provider.TagReconciliationRequired,
			}
		}
	}
	return nil
}

// reconcileSetFailure classifies an ambiguous Set failure. Provider errors
// that definitively reject the request map straight through; transport-class
// failures get one bounded readback of the latest version to decide between
// "not committed" and a PartialCommitError, mirroring the aws provider.
func (p *Provider) reconcileSetFailure(ctx context.Context, key, name string, preVersion int64, cause error) error {
	if errorIsDefinitive(cause) {
		return mapError("set", key, cause)
	}
	observed, err := p.latestVersion(ctx, name)
	if err != nil || observed <= preVersion {
		if observed == 0 {
			return &provider.PartialCommitError{
				Provider:        p.Name(),
				Key:             key,
				PreVersion:      preVersion,
				CommitState:     provider.MutationCommitUnknown,
				ObservedVersion: observed,
				TagState:        provider.TagReconciliationUnknown,
			}
		}
		return mapError("set", key, cause)
	}
	return &provider.PartialCommitError{
		Provider:        p.Name(),
		Key:             key,
		PreVersion:      preVersion,
		Version:         observed,
		ObservedVersion: observed,
		TagState:        provider.TagReconciliationUnknown,
	}
}

// latestVersion reads the current "latest" version number of a secret
// (0 when the secret or any enabled version does not exist).
func (p *Provider) latestVersion(ctx context.Context, name string) (int64, error) {
	secret, err := p.accessVersionRaw(ctx, name+"/versions/latest")
	if err != nil {
		if isNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	return secret.Version, nil
}

func (p *Provider) Delete(ctx context.Context, key string) error {
	id, err := secretID("delete", key)
	if err != nil {
		return err
	}
	if err := p.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{Name: p.secretPath(id)}); err != nil {
		return mapError("delete", key, err)
	}
	return nil
}

func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	id, err := secretID("history", key)
	if err != nil {
		return nil, err
	}
	name := p.secretPath(id)
	versions, err := p.client.ListSecretVersions(ctx, &secretmanagerpb.ListSecretVersionsRequest{
		Parent: name,
		Filter: "state:ENABLED",
	})
	if err != nil {
		return nil, mapError("history", key, err)
	}
	history := make([]*provider.Secret, 0, len(versions))
	for _, v := range versions {
		// The server-side filter already narrowed to ENABLED; re-checking
		// keeps the contract honest for servers that ignore the filter.
		if v.GetState() != secretmanagerpb.SecretVersion_ENABLED {
			continue
		}
		secret, err := p.accessVersionRaw(ctx, v.GetName())
		if err != nil {
			// The version may have been destroyed between the listing and
			// the read; such versions carry no payload anymore and drop out
			// of the history. Anything else is a real failure.
			if isNotFound(err) || isFailedPrecondition(err) {
				continue
			}
			return nil, mapError("history", key, err)
		}
		secret.Key = id
		if v.CreateTime != nil {
			secret.Meta.UpdatedAt = v.CreateTime.AsTime()
		}
		history = append(history, secret)
	}
	sort.Slice(history, func(i, j int) bool { return history[i].Version < history[j].Version })
	return history, nil
}

func (p *Provider) Rollback(ctx context.Context, key string, version int64) error {
	history, err := p.GetHistory(ctx, key)
	if err != nil {
		return err
	}
	var found *provider.Secret
	for _, s := range history {
		if s.Version == version {
			found = s
			break
		}
	}
	if found == nil {
		return provider.ErrNotFound
	}
	return p.Set(ctx, key, found.Value, found.Meta)
}

func (p *Provider) Close() error {
	if c, ok := p.client.(interface{ Close() error }); ok && c != nil {
		return c.Close()
	}
	return nil
}
