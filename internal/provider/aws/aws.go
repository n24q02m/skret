package aws

import (
	"context"

	awslib "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// SSMClient abstracts the AWS SSM API for testability.
type SSMClient interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	GetParametersByPath(ctx context.Context, params *ssm.GetParametersByPathInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error)
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	DeleteParameter(ctx context.Context, params *ssm.DeleteParameterInput, optFns ...func(*ssm.Options)) (*ssm.DeleteParameterOutput, error)
	GetParameterHistory(ctx context.Context, params *ssm.GetParameterHistoryInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterHistoryOutput, error)
}

// Provider wraps AWS SSM Parameter Store.
type Provider struct {
	client SSMClient
	path   string
}

// New creates an AWS SSM provider from resolved config.
func New(cfg *config.ResolvedConfig) (provider.SecretProvider, error) {
	// Use the auth.go helper to load standard credential chain
	awsCfg, err := loadAWSConfig(context.Background(), cfg.Region, cfg.Profile)
	if err != nil {
		return nil, err
	}

	client := ssm.NewFromConfig(awsCfg)
	return &Provider{client: client, path: cfg.Path}, nil
}

// NewWithClient creates a provider with a custom SSM client (for testing).
func NewWithClient(client SSMClient, path string) provider.SecretProvider {
	return &Provider{client: client, path: path}
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
	output, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           awslib.String(key),
		WithDecryption: awslib.Bool(true),
	})
	if err != nil {
		return nil, mapError("get", key, err)
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

func (p *Provider) Set(ctx context.Context, key string, value string, meta *provider.SecretMeta) error {
	input := &ssm.PutParameterInput{
		Name:      awslib.String(key),
		Value:     awslib.String(value),
		Type:      ssmtypes.ParameterTypeSecureString,
		Overwrite: awslib.Bool(true),
	}
	if meta.Description != "" {
		input.Description = awslib.String(meta.Description)
	}
	if len(meta.Tags) > 0 {
		for k, v := range meta.Tags {
			input.Tags = append(input.Tags, ssmtypes.Tag{
				Key:   awslib.String(k),
				Value: awslib.String(v),
			})
		}
	}

	_, err := p.client.PutParameter(ctx, input)
	if err != nil {
		return mapError("set", key, err)
	}
	return nil
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
	return p.Set(ctx, key, found.Value, &found.Meta)
}

func (p *Provider) Close() error { return nil }
