package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// loadAWSConfigFunc is overridable in tests.
var loadAWSConfigFunc = func(ctx context.Context, region, profile string, creds aws.CredentialsProvider) (aws.Config, error) {
	var optFns []func(*config.LoadOptions) error

	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	if creds != nil {
		optFns = append(optFns, config.WithCredentialsProvider(creds))
	} else if profile != "" {
		optFns = append(optFns, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws: load default config: %w", err)
	}

	return cfg, nil
}

func loadAWSConfig(ctx context.Context, region, profile string, creds aws.CredentialsProvider) (aws.Config, error) {
	return loadAWSConfigFunc(ctx, region, profile, creds)
}
