package oci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// SecretsClient abstracts the OCI Secrets service (bundle reads) for
// testability.
type SecretsClient interface {
	GetSecretBundleByName(ctx context.Context, request secrets.GetSecretBundleByNameRequest) (secrets.GetSecretBundleByNameResponse, error)
}

// VaultsClient abstracts the OCI Vault service (secret metadata + writes).
type VaultsClient interface {
	CreateSecret(ctx context.Context, request vault.CreateSecretRequest) (vault.CreateSecretResponse, error)
	UpdateSecret(ctx context.Context, request vault.UpdateSecretRequest) (vault.UpdateSecretResponse, error)
	ListSecrets(ctx context.Context, request vault.ListSecretsRequest) (vault.ListSecretsResponse, error)
	ListSecretVersions(ctx context.Context, request vault.ListSecretVersionsRequest) (vault.ListSecretVersionsResponse, error)
	ScheduleSecretDeletion(ctx context.Context, request vault.ScheduleSecretDeletionRequest) (vault.ScheduleSecretDeletionResponse, error)
}

// TagExpiresAt is the reserved freeform tag mirroring SecretMeta.ExpiresAt
// (`set --ttl` / `rotate --ttl`) into OCI-native metadata.
const TagExpiresAt = "skret-expires-at"

// secretMaxValueKB is the OCI Vault secret-content limit (25 KiB).
const secretMaxValueKB = 25

// Provider wraps OCI Vault secrets (software-protected master key; free
// tier). Values are stored base64-encoded in secret bundles, as the OCI API
// requires; every Set on an existing secret creates a new secret version.
type Provider struct {
	secrets       SecretsClient
	vaults        VaultsClient
	path          string
	compartmentID string
	vaultID       string
	keyID         string
}

var (
	_ provider.SecretProvider  = (*Provider)(nil)
	_ provider.VersionedReader = (*Provider)(nil)
)

// regionOverrideProvider forces one region over the auth source's own
// (the environment `region` field overrides the config-file region).
type regionOverrideProvider struct {
	common.ConfigurationProvider
	region string
}

func (r regionOverrideProvider) Region() (string, error) { return r.region, nil }

// New creates an OCI Vault provider from resolved config. Auth resolves in
// OCI CLI precedence (see resolveConfigurationProvider); `region` in the
// environment config overrides the auth source's region.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	if cfg == nil {
		return nil, errors.New("oci: resolved config is required")
	}
	if cfg.CompartmentID == "" {
		return nil, errors.New("oci: compartment_id is required in the environment config")
	}
	if cfg.VaultID == "" {
		return nil, errors.New("oci: vault_id is required in the environment config")
	}

	authProvider, err := resolveConfigurationProvider(defaultAuthDeps(), cfg.Profile)
	if err != nil {
		return nil, err
	}

	region := cfg.Region
	providerForClients := authProvider
	if region != "" {
		providerForClients = regionOverrideProvider{ConfigurationProvider: authProvider, region: region}
	} else if r, rerr := authProvider.Region(); rerr == nil {
		region = r
	}
	if region == "" {
		return nil, errors.New("oci: no region: set `region` in the environment config or OCI_CLI_REGION")
	}

	secretsClient, err := secrets.NewSecretsClientWithConfigurationProvider(providerForClients)
	if err != nil {
		return nil, fmt.Errorf("oci: create secrets client: %w", err)
	}
	secretsClient.SetRegion(region)
	vaultsClient, err := vault.NewVaultsClientWithConfigurationProvider(providerForClients)
	if err != nil {
		return nil, fmt.Errorf("oci: create vault client: %w", err)
	}
	vaultsClient.SetRegion(region)

	return &Provider{
		secrets:       secretsClient,
		vaults:        vaultsClient,
		path:          cfg.Path,
		compartmentID: cfg.CompartmentID,
		vaultID:       cfg.VaultID,
		keyID:         cfg.KeyID,
	}, nil
}

// NewWithClients creates a provider around custom SDK clients (testing).
func NewWithClients(secretsClient SecretsClient, vaultsClient VaultsClient, path, compartmentID, vaultID, keyID string) *Provider {
	return &Provider{
		secrets:       secretsClient,
		vaults:        vaultsClient,
		path:          path,
		compartmentID: compartmentID,
		vaultID:       vaultID,
		keyID:         keyID,
	}
}

func (p *Provider) Name() string { return "oci" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		Write:      true,
		Versioning: true,
		Tagging:    true,
		AuditLog:   true,
		MaxValueKB: secretMaxValueKB,
	}
}

func (p *Provider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	if p == nil || p.secrets == nil || key == "" {
		return nil, provider.ErrNotFound
	}
	name, err := secretNameFor(p.path, key)
	if err != nil {
		return nil, err
	}
	bundle, err := p.getBundleByName(ctx, name)
	if err != nil {
		return nil, mapError("get", key, err)
	}
	return secretFromBundle(p.path, name, bundle)
}

// GetVersion reads one immutable OCI secret version and verifies that OCI
// returned that exact version.
func (p *Provider) GetVersion(ctx context.Context, key string, version int64) (*provider.Secret, error) {
	if p == nil || p.secrets == nil || key == "" || version <= 0 {
		return nil, provider.ErrNotFound
	}
	name, err := secretNameFor(p.path, key)
	if err != nil {
		return nil, err
	}
	bundle, err := p.getBundleByVersion(ctx, name, version)
	if err != nil {
		return nil, mapError("get_version", key, err)
	}
	if bundle.VersionNumber == nil || *bundle.VersionNumber != version {
		return nil, fmt.Errorf("oci: get_version %q: version mismatch", key)
	}
	return secretFromBundle(p.path, name, bundle)
}

func (p *Provider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	all := make([]*provider.Secret, 0, len(keys))
	for _, key := range keys {
		s, err := p.Get(ctx, key)
		if err != nil {
			if errors.Is(err, provider.ErrNotFound) {
				continue
			}
			return nil, err
		}
		all = append(all, s)
	}
	return all, nil
}

func (p *Provider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	names, err := p.listSecretNames(ctx, pathPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]*provider.Secret, 0, len(names))
	for _, name := range names {
		bundle, err := p.getBundleByName(ctx, name)
		if err != nil {
			return nil, mapError("list", name, err)
		}
		s, err := secretFromBundle(pathPrefix, name, bundle)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *Provider) ListNames(ctx context.Context, pathPrefix string) ([]string, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	names, err := p.listSecretNames(ctx, pathPrefix)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(names))
	for _, name := range names {
		key, ok := secretKeyFor(pathPrefix, name)
		if !ok {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Fingerprint hashes secret name + latest version number per key — bundle
// content is never fetched, so watch polling costs no decryption.
func (p *Provider) Fingerprint(ctx context.Context, pathPrefix string) (string, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	names, err := p.listSecretNames(ctx, pathPrefix)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(names))
	for _, name := range names {
		version, err := p.latestVersion(ctx, name)
		if err != nil {
			return "", mapError("fingerprint", name, err)
		}
		lines = append(lines, fmt.Sprintf("%s@%d", name, version))
	}
	return hashLines(lines), nil
}

func (p *Provider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	name, err := secretNameFor(p.path, key)
	if err != nil {
		return err
	}
	content := &vault.Base64SecretContentDetails{
		Content: common.String(encodeValue(value)),
	}
	tags := freeformTagsFromMeta(meta)

	current, lookupErr := p.getBundleByName(ctx, name)
	switch {
	case lookupErr == nil:
		preVersion := int64(0)
		if current.VersionNumber != nil {
			preVersion = *current.VersionNumber
		}
		details := vault.UpdateSecretDetails{SecretContent: content}
		if meta.Description != "" {
			details.Description = common.String(meta.Description)
		}
		if len(tags) > 0 {
			details.FreeformTags = tags
		}
		if _, err := p.vaults.UpdateSecret(ctx, vault.UpdateSecretRequest{
			SecretId:            current.SecretId,
			UpdateSecretDetails: details,
		}); err != nil {
			if !mutationMayHaveCommitted(err) {
				return mapError("set", key, err)
			}
			return p.reconcileMutation(ctx, key, name, preVersion, err)
		}
		return nil
	case errors.Is(lookupErr, provider.ErrNotFound):
		if p.keyID == "" {
			return fmt.Errorf("oci: set %q: key_id is required in the environment config to create a new secret (a software-protected master key keeps the vault on the free tier)", key)
		}
		details := vault.CreateSecretDetails{
			CompartmentId: common.String(p.compartmentID),
			KeyId:         common.String(p.keyID),
			SecretName:    common.String(name),
			VaultId:       common.String(p.vaultID),
			SecretContent: content,
		}
		if meta.Description != "" {
			details.Description = common.String(meta.Description)
		}
		if len(tags) > 0 {
			details.FreeformTags = tags
		}
		if _, err := p.vaults.CreateSecret(ctx, vault.CreateSecretRequest{CreateSecretDetails: details}); err != nil {
			if !mutationMayHaveCommitted(err) {
				return mapError("set", key, err)
			}
			return p.reconcileMutation(ctx, key, name, 0, err)
		}
		return nil
	default:
		return mapError("set", key, lookupErr)
	}
}

// reconcileMutation reports an ambiguous write outcome after readback:
// the committed value either landed (partial commit, unknown outcome vs
// pre-version) or definitively did not (mapped original error).
func (p *Provider) reconcileMutation(ctx context.Context, key, name string, preVersion int64, cause error) error {
	bundle, err := p.getBundleByName(ctx, name)
	if err != nil || bundle.VersionNumber == nil {
		return mapError("set", key, cause)
	}
	observed := *bundle.VersionNumber
	if observed <= preVersion {
		return mapError("set", key, cause)
	}
	return &provider.PartialCommitError{
		Provider:        p.Name(),
		Key:             key,
		PreVersion:      preVersion,
		CommitState:     provider.MutationCommitUnknown,
		Version:         0,
		ObservedVersion: observed,
	}
}

func (p *Provider) Delete(ctx context.Context, key string) error {
	name, err := secretNameFor(p.path, key)
	if err != nil {
		return err
	}
	secretID, err := p.secretIDForName(ctx, name)
	if err != nil {
		return mapError("delete", key, err)
	}
	// An empty ScheduleSecretDeletionDetails means the secret is deleted
	// immediately (OCI default when no time is given), matching the AWS
	// provider's synchronous Delete.
	if _, err := p.vaults.ScheduleSecretDeletion(ctx, vault.ScheduleSecretDeletionRequest{
		SecretId:                      common.String(secretID),
		ScheduleSecretDeletionDetails: vault.ScheduleSecretDeletionDetails{},
	}); err != nil {
		return mapError("delete", key, err)
	}
	return nil
}

// GetHistory returns every version of a secret, oldest first, with values
// decoded from each version's bundle.
func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	name, err := secretNameFor(p.path, key)
	if err != nil {
		return nil, err
	}
	current, err := p.getBundleByName(ctx, name)
	if err != nil {
		return nil, mapError("history", key, err)
	}
	versions, err := p.listVersions(ctx, derefString(current.SecretId))
	if err != nil {
		return nil, mapError("history", key, err)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i] < versions[j]
	})
	out := make([]*provider.Secret, 0, len(versions))
	for _, v := range versions {
		bundle, err := p.getBundleByVersion(ctx, name, v)
		if err != nil {
			return nil, mapError("history", key, err)
		}
		s, err := secretFromBundle(p.path, name, bundle)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *Provider) Rollback(ctx context.Context, key string, version int64) error {
	s, err := p.GetVersion(ctx, key, version)
	if err != nil {
		return err
	}
	return p.Set(ctx, key, s.Value, s.Meta)
}

func (p *Provider) Close() error { return nil }

// getBundleByName fetches the current bundle for a secret name.
func (p *Provider) getBundleByName(ctx context.Context, name string) (secrets.SecretBundle, error) {
	resp, err := p.secrets.GetSecretBundleByName(ctx, secrets.GetSecretBundleByNameRequest{
		VaultId:    common.String(p.vaultID),
		SecretName: common.String(name),
	})
	if err != nil {
		return secrets.SecretBundle{}, mapError("get", name, err)
	}
	return resp.SecretBundle, nil
}

// getBundleByVersion fetches one exact version's bundle.
func (p *Provider) getBundleByVersion(ctx context.Context, name string, version int64) (secrets.SecretBundle, error) {
	resp, err := p.secrets.GetSecretBundleByName(ctx, secrets.GetSecretBundleByNameRequest{
		VaultId:       common.String(p.vaultID),
		SecretName:    common.String(name),
		VersionNumber: common.Int64(version),
	})
	if err != nil {
		return secrets.SecretBundle{}, mapError("get", name, err)
	}
	return resp.SecretBundle, nil
}

// listSecretNames returns, sorted, the names of ACTIVE secrets in the
// vault belonging to pathPrefix.
func (p *Provider) listSecretNames(ctx context.Context, pathPrefix string) ([]string, error) {
	var names []string
	var page *string
	for {
		resp, err := p.vaults.ListSecrets(ctx, vault.ListSecretsRequest{
			CompartmentId:  common.String(p.compartmentID),
			VaultId:        common.String(p.vaultID),
			LifecycleState: vault.SecretSummaryLifecycleStateActive,
			Page:           page,
		})
		if err != nil {
			return nil, mapError("list", pathPrefix, err)
		}
		for i := range resp.Items {
			name := derefString(resp.Items[i].SecretName)
			if _, ok := secretKeyFor(pathPrefix, name); ok {
				names = append(names, name)
			}
		}
		if resp.OpcNextPage == nil {
			break
		}
		page = resp.OpcNextPage
	}
	sort.Strings(names)
	return names, nil
}

// secretIDForName resolves the OCID of an ACTIVE secret by exact name.
func (p *Provider) secretIDForName(ctx context.Context, name string) (string, error) {
	var page *string
	for {
		resp, err := p.vaults.ListSecrets(ctx, vault.ListSecretsRequest{
			CompartmentId:  common.String(p.compartmentID),
			VaultId:        common.String(p.vaultID),
			Name:           common.String(name),
			LifecycleState: vault.SecretSummaryLifecycleStateActive,
			Page:           page,
		})
		if err != nil {
			return "", err
		}
		for i := range resp.Items {
			if derefString(resp.Items[i].SecretName) == name {
				return derefString(resp.Items[i].Id), nil
			}
		}
		if resp.OpcNextPage == nil {
			break
		}
		page = resp.OpcNextPage
	}
	return "", provider.ErrNotFound
}

// listVersions returns every version number of a secret, paginated.
func (p *Provider) listVersions(ctx context.Context, secretID string) ([]int64, error) {
	var versions []int64
	var page *string
	for {
		resp, err := p.vaults.ListSecretVersions(ctx, vault.ListSecretVersionsRequest{
			SecretId: common.String(secretID),
			Page:     page,
		})
		if err != nil {
			return nil, err
		}
		for i := range resp.Items {
			if v := resp.Items[i].VersionNumber; v != nil {
				versions = append(versions, *v)
			}
		}
		if resp.OpcNextPage == nil {
			break
		}
		page = resp.OpcNextPage
	}
	return versions, nil
}

// latestVersion returns the newest version number of a secret (metadata
// read only).
func (p *Provider) latestVersion(ctx context.Context, name string) (int64, error) {
	bundle, err := p.getBundleByName(ctx, name)
	if err != nil {
		return 0, err
	}
	versions, err := p.listVersions(ctx, derefString(bundle.SecretId))
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, fmt.Errorf("oci: secret %q has no versions", name)
	}
	newest := versions[0]
	for _, v := range versions[1:] {
		if v > newest {
			newest = v
		}
	}
	return newest, nil
}

// secretFromBundle decodes a bundle into a skret Secret; the Key is the
// full skret key reconstructed from the provider path.
func secretFromBundle(pathPrefix, name string, bundle secrets.SecretBundle) (*provider.Secret, error) {
	value, err := decodeBundle(bundle)
	if err != nil {
		return nil, err
	}
	key, ok := secretKeyFor(pathPrefix, name)
	if !ok {
		key = name
	}
	s := &provider.Secret{
		Key:     key,
		Value:   value,
		Version: derefInt64(bundle.VersionNumber),
	}
	if bundle.TimeCreated != nil {
		s.Meta.UpdatedAt = bundle.TimeCreated.Time
	}
	return s, nil
}

// decodeBundle extracts the base64-encoded secret content.
func decodeBundle(bundle secrets.SecretBundle) (string, error) {
	content, ok := bundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil {
		return "", fmt.Errorf("oci: secret bundle %q has no base64 content", derefString(bundle.SecretId))
	}
	raw, err := base64.StdEncoding.DecodeString(*content.Content)
	if err != nil {
		return "", fmt.Errorf("oci: decode secret content: %w", err)
	}
	return string(raw), nil
}

func encodeValue(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

// freeformTagsFromMeta renders SecretMeta as sorted freeform tags. A
// non-zero ExpiresAt mirrors to TagExpiresAt and wins over a user-supplied
// tag of the same name (the timestamp is the authoritative source).
func freeformTagsFromMeta(meta provider.SecretMeta) map[string]string {
	if len(meta.Tags) == 0 && meta.ExpiresAt.IsZero() {
		return nil
	}
	merged := make(map[string]string, len(meta.Tags)+1)
	for key, val := range meta.Tags {
		merged[key] = val
	}
	if !meta.ExpiresAt.IsZero() {
		merged[TagExpiresAt] = meta.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return merged
}

// derefString reads a *string as "" when nil.
func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// derefInt64 reads an *int64 as 0 when nil.
func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// hashLines returns a stable sha256 hex digest of lines, independent of
// order.
func hashLines(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(joined)))
}
