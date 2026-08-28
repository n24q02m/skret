package aws

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// SSMClient abstracts the AWS SSM API for testability.
type SSMClient interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParameters(ctx context.Context, params *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	DeleteParameter(ctx context.Context, params *ssm.DeleteParameterInput, optFns ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)
	GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
}

type ssmTagger interface {
	AddTagsToResource(ctx context.Context, params *ssm.AddTagsToResourceInput, optFns ...func(*ssm.Options)) (*ssm.AddTagsToResourceOutput, error)
}

type ssmTagReader interface {
	ListTagsForResource(ctx context.Context, params *ssm.ListTagsForResourceInput, optFns ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
}

// Readback has its own bounded budget so a tag failure cannot leave the caller
// waiting indefinitely while the committed value remains ambiguous.
const mutationReadbackTimeout = 5 * time.Second

// Provider wraps AWS SSM Parameter Store.
type Provider struct {
	client   SSMClient
	path     string
	kmsKeyID string
}

// New creates an AWS SSM provider from resolved config.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	// Prefer a skret-stored credential (skret auth login aws ...) so skret
	// authenticates on its own; fall back to the standard SDK credential
	// chain (aws login / env / shared profile / OIDC) when none is stored.
	creds, storedProfile, _ := resolveStoredCredentials()

	profile := cfg.Profile
	if profile == "" {
		profile = storedProfile
	}

	awsCfg, err := loadAWSConfig(context.Background(), cfg.Region, profile, creds)
	if err != nil {
		return nil, err
	}

	// SSM PutParameter is throttled at ~3 TPS/account. Default SDK retry (3
	// attempts) is too aggressive for batch imports of 40+ keys. Configure
	// AdaptiveMode with higher MaxAttempts + longer MaxBackoff so import
	// sweeps survive sustained throttling instead of partially applying.
	client := ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
		o.Retryer = retry.NewAdaptiveMode(func(ao *retry.AdaptiveModeOptions) {
			ao.StandardOptions = append(ao.StandardOptions, func(so *retry.StandardOptions) {
				so.MaxAttempts = 10
				so.MaxBackoff = 20 * time.Second
			})
		})
	})
	return &Provider{client: client, path: cfg.Path, kmsKeyID: cfg.KMSKeyID}, nil
}

// NewWithClient creates a provider with a custom SSM client (for testing).
func NewWithClient(client SSMClient, path string, kmsKeyID ...string) provider.SecretProvider {
	keyID := ""
	if len(kmsKeyID) > 0 {
		keyID = kmsKeyID[0]
	}
	return &Provider{client: client, path: path, kmsKeyID: keyID}
}

func (p *Provider) Name() string { return "aws" }

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		Write:      true,
		Versioning: true,
		Tagging:    true,
		AuditLog:   true,
		MaxValueKB: 4,
	}
}

func (p *Provider) Get(ctx context.Context, key string) (*provider.Secret, error) {
	if p == nil || p.client == nil || key == "" {
		return nil, provider.ErrNotFound
	}
	output, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awslib.String(key),
		WithDecryption: awslib.Bool(true),
	})
	if err != nil {
		return nil, mapError("get", key, err)
	}
	if output == nil || output.Parameter == nil {
		return nil, provider.ErrNotFound
	}
	param := output.Parameter
	s := &provider.Secret{
		Key:     awslib.ToString(param.Name),
		Value:   awslib.ToString(param.Value),
		Version: param.Version,
	}
	if param.LastModifiedDate != nil {
		s.Meta.UpdatedAt = *param.LastModifiedDate
	}
	return s, nil
}

// GetVersion reads one immutable SSM parameter version using the documented
// name:version selector and verifies that AWS returned that exact version.
func (p *Provider) GetVersion(ctx context.Context, key string, version int64) (*provider.Secret, error) {
	if p == nil || p.client == nil || key == "" || version <= 0 {
		return nil, provider.ErrNotFound
	}
	selector := key + ":" + strconv.FormatInt(version, 10)
	output, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awslib.String(selector),
		WithDecryption: awslib.Bool(true),
	})
	if err != nil {
		return nil, mapError("get_version", key, err)
	}
	if output == nil || output.Parameter == nil || output.Parameter.Version != version {
		return nil, provider.ErrNotFound
	}
	parameter := output.Parameter
	secret := &provider.Secret{
		Key:     awslib.ToString(parameter.Name),
		Value:   awslib.ToString(parameter.Value),
		Version: parameter.Version,
	}
	if parameter.LastModifiedDate != nil {
		secret.Meta.UpdatedAt = *parameter.LastModifiedDate
	}
	return secret, nil
}

func (p *Provider) GetBatch(ctx context.Context, keys []string) ([]*provider.Secret, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	// Pre-allocate to the max possible result size (one secret per key) so the
	// append calls inside the chunking loop don't trigger slice reallocation.
	allSecrets := make([]*provider.Secret, 0, len(keys))
	for i := 0; i < len(keys); i += 10 {
		end := i + 10
		if end > len(keys) {
			end = len(keys)
		}
		batch := keys[i:end]

		output, err := p.client.GetParameters(ctx, &ssm.GetParametersInput{
			Names:          batch,
			WithDecryption: awslib.Bool(true),
		})
		if err != nil {
			return nil, mapError("get_batch", batch[0], err)
		}

		for i := range output.Parameters {
			param := output.Parameters[i]
			s := &provider.Secret{
				Key:     awslib.ToString(param.Name),
				Value:   awslib.ToString(param.Value),
				Version: param.Version,
			}
			if param.LastModifiedDate != nil {
				s.Meta.UpdatedAt = *param.LastModifiedDate
			}
			allSecrets = append(allSecrets, s)
		}
	}
	return allSecrets, nil
}

func (p *Provider) List(ctx context.Context, pathPrefix string) ([]*provider.Secret, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	var secrets []*provider.Secret
	var nextToken *string

	for {
		output, err := p.client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           awslib.String(pathPrefix),
			Recursive:      awslib.Bool(true),
			WithDecryption: awslib.Bool(true),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, mapError("list", pathPrefix, err)
		}

		for i := range output.Parameters {
			param := output.Parameters[i]
			s := &provider.Secret{
				Key:     awslib.ToString(param.Name),
				Value:   awslib.ToString(param.Value),
				Version: param.Version,
			}
			if param.LastModifiedDate != nil {
				s.Meta.UpdatedAt = *param.LastModifiedDate
			}
			secrets = append(secrets, s)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return secrets, nil
}

func (p *Provider) ListNames(ctx context.Context, pathPrefix string) ([]string, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	var names []string
	var nextToken *string
	for {
		output, err := p.client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           awslib.String(pathPrefix),
			Recursive:      awslib.Bool(true),
			WithDecryption: awslib.Bool(false),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, mapError("list", pathPrefix, err)
		}
		for i := range output.Parameters {
			names = append(names, awslib.ToString(output.Parameters[i].Name))
		}
		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return names, nil
}

func (p *Provider) Fingerprint(ctx context.Context, pathPrefix string) (string, error) {
	if pathPrefix == "" {
		pathPrefix = p.path
	}
	var lines []string
	var nextToken *string
	for {
		out, err := p.client.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           awslib.String(pathPrefix),
			Recursive:      awslib.Bool(true),
			WithDecryption: awslib.Bool(false),
			NextToken:      nextToken,
		})
		if err != nil {
			return "", mapError("fingerprint", pathPrefix, err)
		}
		for i := range out.Parameters {
			lines = append(lines, fmt.Sprintf("%s@%d",
				awslib.ToString(out.Parameters[i].Name), out.Parameters[i].Version))
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return hashLines(lines), nil
}

// hashLines returns a stable sha256 hex digest of lines, independent of order.
func hashLines(lines []string) string {
	sorted := make([]string, len(lines))
	copy(sorted, lines)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(joined)))
}

func (p *Provider) Set(ctx context.Context, key string, value string, meta provider.SecretMeta) error {
	_, lookupErr := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name: awslib.String(key),
	})
	exists := lookupErr == nil
	if lookupErr != nil {
		var notFound *ssmtypes.ParameterNotFound
		if !errors.As(lookupErr, &notFound) {
			return mapError("set", key, lookupErr)
		}
	}

	input := &ssm.PutParameterInput{
		Name:      awslib.String(key),
		Value:     awslib.String(value),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: awslib.Bool(true),
	}
	if p.kmsKeyID != "" {
		input.KeyId = awslib.String(p.kmsKeyID)
	}
	if meta.Description != "" {
		input.Description = awslib.String(meta.Description)
	}
	tags := tagsFromMeta(meta)
	if !exists {
		input.Tags = tags
	}

	putOutput, err := p.client.PutParameter(ctx, input)
	if err != nil {
		return mapError("set", key, err)
	}
	if exists && len(tags) > 0 {
		tagger, ok := p.client.(ssmTagger)
		if !ok {
			return p.partialCommit(ctx, key, putOutput, tags)
		}
		if _, err := tagger.AddTagsToResource(ctx, &ssm.AddTagsToResourceInput{
			ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
			ResourceId:   awslib.String(key),
			Tags:         tags,
		}); err != nil {
			return p.partialCommit(ctx, key, putOutput, tags)
		}
	}
	return nil
}

func (p *Provider) partialCommit(
	ctx context.Context,
	key string,
	putOutput *ssm.PutParameterOutput,
	tags []ssmtypes.Tag,
) error {
	var committedVersion int64
	if putOutput != nil {
		committedVersion = putOutput.Version
	}
	observedVersion, tagsMatch, tagState := p.readbackMutation(ctx, key, committedVersion, tags)
	if committedVersion == 0 {
		committedVersion = observedVersion
	}
	if tagsMatch && committedVersion > 0 && observedVersion == committedVersion {
		return nil
	}
	return &provider.PartialCommitError{
		Provider:        p.Name(),
		Key:             key,
		Version:         committedVersion,
		ObservedVersion: observedVersion,
		TagState:        tagState,
	}
}

func (p *Provider) readbackMutation(
	ctx context.Context,
	key string,
	expectedVersion int64,
	expectedTags []ssmtypes.Tag,
) (int64, bool, string) {
	readCtx, cancel := context.WithTimeout(ctx, mutationReadbackTimeout)
	defer cancel()
	output, err := p.client.GetParameter(readCtx, &ssm.GetParameterInput{Name: awslib.String(key)})
	if err != nil || output == nil || output.Parameter == nil {
		return 0, false, provider.TagReconciliationUnknown
	}
	observedVersion := output.Parameter.Version
	if expectedVersion > 0 && observedVersion != expectedVersion {
		return observedVersion, false, provider.TagReconciliationRequired
	}
	reader, ok := p.client.(ssmTagReader)
	if !ok {
		return observedVersion, false, provider.TagReconciliationUnknown
	}
	tagOutput, err := reader.ListTagsForResource(readCtx, &ssm.ListTagsForResourceInput{
		ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
		ResourceId:   awslib.String(key),
	})
	if err != nil || tagOutput == nil {
		return observedVersion, false, provider.TagReconciliationUnknown
	}
	if equalTags(tagOutput.TagList, expectedTags) {
		return observedVersion, true, ""
	}
	return observedVersion, false, provider.TagReconciliationRequired
}

func equalTags(first, second []ssmtypes.Tag) bool {
	if len(first) != len(second) {
		return false
	}
	observed := make(map[string]string, len(first))
	for _, tag := range first {
		key := awslib.ToString(tag.Key)
		if _, exists := observed[key]; exists {
			return false
		}
		observed[key] = awslib.ToString(tag.Value)
	}
	for _, tag := range second {
		key := awslib.ToString(tag.Key)
		value, exists := observed[key]
		if !exists || value != awslib.ToString(tag.Value) {
			return false
		}
	}
	return true
}

func tagsFromMeta(meta provider.SecretMeta) []ssmtypes.Tag {
	keys := make([]string, 0, len(meta.Tags))
	for key := range meta.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tags := make([]ssmtypes.Tag, 0, len(keys))
	for _, key := range keys {
		tags = append(tags, ssmtypes.Tag{
			Key:   awslib.String(key),
			Value: awslib.String(meta.Tags[key]),
		})
	}
	return tags
}

func (p *Provider) Delete(ctx context.Context, key string) error {
	_, err := p.client.DeleteParameter(ctx, &ssm.DeleteParameterInput{
		Name: awslib.String(key),
	})
	if err != nil {
		return mapError("delete", key, err)
	}
	return nil
}

func (p *Provider) GetHistory(ctx context.Context, key string) ([]*provider.Secret, error) {
	var secrets []*provider.Secret
	var nextToken *string

	for {
		output, err := p.client.GetParameterHistory(ctx, &ssm.GetParameterHistoryInput{
			Name:           awslib.String(key),
			WithDecryption: awslib.Bool(true),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, mapError("history", key, err)
		}

		for i := range output.Parameters {
			param := output.Parameters[i]
			s := &provider.Secret{
				Key:     awslib.ToString(param.Name),
				Value:   awslib.ToString(param.Value),
				Version: param.Version,
			}
			if param.LastModifiedDate != nil {
				s.Meta.UpdatedAt = *param.LastModifiedDate
			}
			secrets = append(secrets, s)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
	return secrets, nil
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

func (p *Provider) Close() error { return nil }
