package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// loadAWSConfig creates an AWS configuration instance using the standard SDK credential chain.
// It applies the region and profile if specified.
func loadAWSConfig(ctx context.Context, region, profile string) (aws.Config, error) {
	var optFns []func(*config.LoadOptions) error

	if region != "" {
		optFns = append(optFns, config.WithRegion(region))
	}
	if profile != "" {
		optFns = append(optFns, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws: load default config: %w", err)
	}

	return cfg, nil
}
