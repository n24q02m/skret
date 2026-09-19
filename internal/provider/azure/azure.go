// Package azure implements the SecretProvider contract against Azure Key
// Vault secrets using the azsecrets track-2 SDK.
//
// Naming: Key Vault secret names accept only alphanumeric characters and
// dashes (1-127 chars). skret keys are sanitized on both read and write
// paths (see sanitizeKey), so `set DB_URL` stores `DB-URL` and `get DB_URL`
// reads it back. The mapping is deterministic but lossy (underscore and
// dash keys collide); this is documented provider behavior, matching how
// the sanitized key is the only name Key Vault ever sees.
//
// Versioning: Key Vault versions are 32-char hex IDs, while the provider
// contract carries int64 version numbers. versionNumber folds the ID into
// the positive int64 space deterministically; GetVersion reverses the fold
// by enumerating the secret's version IDs.
package azure

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// SecretsClient abstracts the azsecrets API surface skret uses so contract
// tests can substitute an in-memory Key Vault (the SSMClient pattern the
// AWS provider uses). *azsecrets.Client satisfies it.
type SecretsClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesResponse]
	NewListSecretPropertiesVersionsPager(name string, options *azsecrets.ListSecretPropertiesVersionsOptions) *azruntime.Pager[azsecrets.ListSecretPropertiesVersionsResponse]
}

// Reserved skret tags mirrored into Key Vault secret tags. The expires-at
// tag matches the AWS provider's TagExpiresAt so the same metadata survives
// a provider switch. A non-zero SecretMeta.ExpiresAt always wins over a
// user-supplied tag of the same name (the timestamp is authoritative).
const (
	TagExpiresAt   = "skret-expires-at"
	TagDescription = "skret-description"
)

// ContentTypePlain marks skret-written secrets so operators can tell them
// from certificate-backing or manually-created secrets in the portal.
const ContentTypePlain = "text/plain; charset=utf-8"

// Readback has its own bounded budget so an ambiguous write cannot leave
// the caller waiting indefinitely while the mutation stays unresolved.
const mutationReadbackTimeout = 5 * time.Second

// Provider wraps an Azure Key Vault secrets client.
type Provider struct {
	client SecretsClient
	// prefix is the optional name-prefix filter applied by List, ListNames,
	// and Fingerprint (config `path`, slash-trimmed). Key Vault names are
	// flat, so this is a literal string prefix on sanitized names, not a
	// hierarchy.
	prefix string
}

// New creates an Azure Key Vault provider from resolved config. One of
// cfg.VaultURL or cfg.VaultName is required; credentials come from the
// DefaultAzureCredential chain (AZURE_TENANT_ID/AZURE_CLIENT_ID/
// AZURE_CLIENT_SECRET env vars, managed identity, Azure CLI).
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	vaultURL, err := ResolveVaultURL(cfg.VaultURL, cfg.VaultName)
	if err != nil {
		return nil, err
	}
	client, err := newDefaultClient(vaultURL)
	if err != nil {
		return nil, err
	}
	return &Provider{client: client, prefix: prefixFilter(cfg.Path)}, nil
}

// NewWithClient creates a provider with a custom secrets client (testing).
func NewWithClient(client SecretsClient, prefix string) provider.SecretProvider {
	return &Provider{client: client, prefix: prefixFilter(prefix)}
}

func (p *Provider) Name() string { return "azure" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		Write:      true,
		Versioning: true,
		Tagging:    true,
		// Rotation is vault-side (Event Grid policies), not provider-side:
		// skret rotate re-PUTs values itself, so it needs no capability bit.
		AuditLog:   true,
		MaxValueKB: 25,
	}
}

// prefixFilter normalizes a path-prefix config into a literal name prefix.
// Key Vault names never contain slashes (sanitization replaces them), so
// both "/myapp/prod" and "myapp-prod" mean "names starting with myapp-prod".
func prefixFilter(path string) string {
	return strings.Trim(path, "/")
}

func (p *Provider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	name, err := sanitizeKey(key)
	if err != nil {
		// A name Key Vault can never hold reads as absent, matching the
		// AWS provider's empty-key handling.
		return nil, fmt.Errorf("azure: get %q: %w", key, provider.ErrNotFound)
	}
	resp, err := p.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return nil, mapError("get", key, err)
	}
	// Reads echo the caller's key form; Secret.Key carries the request, not
	// the sanitized vault name (secretlaunch pins launches on key equality).
	return secretFromResponse(key, resp.Secret), nil
}

// GetVersion reads one immutable Key Vault version. It implements
// provider.VersionedReader; the returned Secret.Version is exactly the
// requested number (secretlaunch verifies this equality).
func (p *Provider) GetVersion(ctx context.Context, key string, version int64) (*provider.Secret, error) {
	name, err := sanitizeKey(key)
	if err != nil || version <= 0 {
		return nil, fmt.Errorf("azure: get_version %q: %w", key, provider.ErrNotFound)
	}
	versionID, err := p.resolveVersionNumber(ctx, name, version)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.GetSecret(ctx, name, versionID, nil)
	if err != nil {
		return nil, mapError("get_version", key, err)
	}
	secret := secretFromResponse(key, resp.Secret)
	secret.Version = version
	return secret, nil
}

// resolveVersionNumber enumerates the secret's version IDs (metadata only,
// no value reads) and returns the full version ID whose folded number
// matches want. Enumeration makes the mapping stateless: any number this
// provider ever returned resolves again, from any process.
func (p *Provider) resolveVersionNumber(ctx context.Context, name string, want int64) (string, error) {
	pager := p.client.NewListSecretPropertiesVersionsPager(name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", mapError("get_version", name, err)
		}
		for _, prop := range page.Value {
			if prop == nil || prop.ID == nil {
				continue
			}
			if versionNumber(prop.ID.Version()) == want {
				return prop.ID.Version(), nil
			}
		}
	}
	return "", fmt.Errorf("azure: get_version %q: %w", name, provider.ErrNotFound)
}

// GetBatch reads keys one by one (Key Vault has no batch-read API) and
// skips missing or unsanitizable keys, matching the AWS provider's
// GetParameters behavior. Results keep the input order of the found keys.
func (p *Provider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := make([]*provider.Secret, 0, len(keys))
	for _, key := range keys {
		secret, err := p.Get(ctx, key)
		if err != nil {
			continue
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (p *Provider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	filter := p.filterFor(pathPrefix)
	secrets := make([]*provider.Secret, 0)
	pager := p.client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, mapError("list", filter, err)
		}
		for _, prop := range page.Value {
			name, versionID, ok := listableName(prop, filter)
			if !ok {
				continue
			}
			resp, err := p.client.GetSecret(ctx, name, versionID, nil)
			if err != nil {
				return nil, mapError("list", name, err)
			}
			secrets = append(secrets, secretFromResponse(name, resp.Secret))
		}
	}
	return secrets, nil
}

func (p *Provider) ListNames(ctx context.Context, pathPrefix string) ([]string, error) {
	filter := p.filterFor(pathPrefix)
	names := make([]string, 0)
	pager := p.client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, mapError("list", filter, err)
		}
		for _, prop := range page.Value {
			name, _, ok := listableName(prop, filter)
			if !ok {
				continue
			}
			names = append(names, name)
		}
	}
	return names, nil
}

// Fingerprint hashes "name@version" lines (metadata only, no value reads),
// mirroring the AWS provider's watch-detection contract.
func (p *Provider) Fingerprint(ctx context.Context, pathPrefix string) (string, error) {
	filter := p.filterFor(pathPrefix)
	var lines []string
	pager := p.client.NewListSecretPropertiesPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", mapError("fingerprint", filter, err)
		}
		for _, prop := range page.Value {
			name, versionID, ok := listableName(prop, filter)
			if !ok {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s@%d", name, versionNumber(versionID)))
		}
	}
	return hashLines(lines), nil
}

// listableName extracts the name/version pair of a listed secret when it
// passes the prefix filter and is not a managed (certificate-backed)
// secret skret must not surface as config.
func listableName(prop *azsecrets.SecretProperties, filter string) (name, versionID string, ok bool) {
	if prop == nil || prop.ID == nil {
		return "", "", false
	}
	if prop.Managed != nil && *prop.Managed {
		return "", "", false
	}
	name = prop.ID.Name()
	versionID = prop.ID.Version()
	if filter != "" && !strings.HasPrefix(name, filter) {
		return "", "", false
	}
	return name, versionID, true
}

func (p *Provider) filterFor(pathPrefix string) string {
	if pathPrefix != "" {
		return prefixFilter(pathPrefix)
	}
	return p.prefix
}

// hashLines returns a stable sha256 hex digest of lines, independent of order.
func hashLines(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(joined)))
}

// Set writes value as a new Key Vault version. The PUT carries value, tags,
// and content type in one atomic request, so unlike the AWS provider's
// put-then-tag sequence there is no tag half-committed state; the only
// ambiguity is a lost response after commit, which the readback reconciles.
func (p *Provider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	name, err := sanitizeKey(key)
	if err != nil {
		return fmt.Errorf("azure: set %q: %w", key, err)
	}
	// Pre-write readback for partial-commit attribution (the AWS pattern):
	// the latest version number before the write is the baseline the
	// reconciliation compares against.
	preVersion := int64(0)
	pre, err := p.client.GetSecret(ctx, name, "", nil)
	switch {
	case err == nil && pre.ID != nil:
		preVersion = versionNumber(pre.ID.Version())
	case isNotFound(err):
		// New secret: baseline 0.
	case err != nil:
		return mapError("set", key, err)
	}

	params := azsecrets.SetSecretParameters{
		Value:       &value,
		ContentType: new(ContentTypePlain),
		Tags:        tagsFromMeta(meta),
	}
	if _, err := p.client.SetSecret(ctx, name, params, nil); err != nil {
		if !setErrorMayHaveCommitted(err) {
			return mapError("set", key, err)
		}
		return p.reconcileSetFailure(ctx, key, name, value, meta, preVersion, err)
	}
	return nil
}

// reconcileSetFailure classifies an ambiguous write. A new version whose
// value and tags match the request proves the whole write landed (the PUT
// is atomic); a version bump with different content means another writer
// raced us; no new version means the write never committed.
func (p *Provider) reconcileSetFailure(
	ctx context.Context,
	key string,
	name string,
	value string,
	meta provider.SecretMeta,
	preVersion int64,
	cause error,
) error {
	readCtx, cancel := context.WithTimeout(ctx, mutationReadbackTimeout)
	defer cancel()
	resp, err := p.client.GetSecret(readCtx, name, "", nil)
	if err != nil || resp.ID == nil {
		return &provider.PartialCommitError{
			Provider:        p.Name(),
			Key:             key,
			PreVersion:      preVersion,
			CommitState:     provider.MutationCommitUnknown,
			ObservedVersion: 0,
			TagState:        provider.TagReconciliationUnknown,
		}
	}
	observed := versionNumber(resp.ID.Version())
	if observed == preVersion {
		return mapError("set", key, cause)
	}
	if resp.Value != nil && *resp.Value == value && tagsEqual(resp.Tags, tagsFromMeta(meta)) {
		return nil
	}
	return &provider.PartialCommitError{
		Provider:        p.Name(),
		Key:             key,
		PreVersion:      preVersion,
		Version:         observed,
		ObservedVersion: observed,
		TagState:        provider.TagReconciliationRequired,
	}
}

// Delete soft-deletes the secret (recoverable for the vault's retention
// window; skret never purges). Key Vault's delete is synchronous.
func (p *Provider) Delete(ctx context.Context, key string) error {
	name, err := sanitizeKey(key)
	if err != nil {
		return fmt.Errorf("azure: delete %q: %w", key, provider.ErrNotFound)
	}
	if _, err := p.client.DeleteSecret(ctx, name, nil); err != nil {
		return mapError("delete", key, err)
	}
	return nil
}

// GetHistory returns every version of the secret with values, oldest
// first (Key Vault lists newest-first; the order is reversed to match the
// AWS provider's ascending history).
func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	name, err := sanitizeKey(key)
	if err != nil {
		return nil, fmt.Errorf("azure: history %q: %w", key, provider.ErrNotFound)
	}
	secrets := make([]*provider.Secret, 0)
	pager := p.client.NewListSecretPropertiesVersionsPager(name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, mapError("history", key, err)
		}
		for _, prop := range page.Value {
			if prop == nil || prop.ID == nil {
				continue
			}
			versionID := prop.ID.Version()
			resp, err := p.client.GetSecret(ctx, name, versionID, nil)
			if err != nil {
				return nil, mapError("history", key, err)
			}
			secrets = append(secrets, secretFromResponse(key, resp.Secret))
		}
	}
	for i, j := 0, len(secrets)-1; i < j; i, j = i+1, j-1 {
		secrets[i], secrets[j] = secrets[j], secrets[i]
	}
	return secrets, nil
}

// Rollback re-PUTs an old version's value as a new version (Key Vault
// versions are immutable), matching the AWS provider.
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

func (p *Provider) Close() error { return nil }

// secretFromResponse maps an azsecrets response into the provider contract.
// Reserved tags round-trip back into SecretMeta (expires-at, description);
// everything else lands in Meta.Tags.
func secretFromResponse(name string, s azsecrets.Secret) *provider.Secret {
	secret := &provider.Secret{Key: name}
	if s.Value != nil {
		secret.Value = *s.Value
	}
	if s.ID != nil {
		secret.Version = versionNumber(s.ID.Version())
	}
	if s.Attributes != nil {
		if s.Attributes.Created != nil {
			secret.Meta.CreatedAt = *s.Attributes.Created
		}
		if s.Attributes.Updated != nil {
			secret.Meta.UpdatedAt = *s.Attributes.Updated
		}
	}
	for tagKey, tagValue := range s.Tags {
		if tagValue == nil {
			continue
		}
		switch tagKey {
		case TagExpiresAt:
			if ts, err := time.Parse(time.RFC3339, *tagValue); err == nil {
				secret.Meta.ExpiresAt = ts
			}
		case TagDescription:
			secret.Meta.Description = *tagValue
		default:
			if secret.Meta.Tags == nil {
				secret.Meta.Tags = make(map[string]string)
			}
			secret.Meta.Tags[tagKey] = *tagValue
		}
	}
	return secret
}

// tagsFromMeta renders SecretMeta as Key Vault tags. A non-zero ExpiresAt
// mirrors to TagExpiresAt and wins over a user-supplied tag of the same
// name; a zero ExpiresAt drops the reserved tag so it is never echoed
// stale onto the new version.
func tagsFromMeta(meta provider.SecretMeta) map[string]*string {
	merged := make(map[string]*string, len(meta.Tags)+2)
	for tagKey, tagValue := range meta.Tags {
		merged[tagKey] = new(tagValue)
	}
	delete(merged, TagExpiresAt)
	if !meta.ExpiresAt.IsZero() {
		merged[TagExpiresAt] = new(meta.ExpiresAt.UTC().Format(time.RFC3339))
	}
	delete(merged, TagDescription)
	if meta.Description != "" {
		merged[TagDescription] = new(meta.Description)
	}
	return merged
}

func tagsEqual(first, second map[string]*string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, fv := range first {
		sv, ok := second[key]
		if !ok {
			return false
		}
		switch {
		case fv == nil && sv == nil:
		case fv == nil || sv == nil:
			return false
		case *fv != *sv:
			return false
		}
	}
	return true
}
