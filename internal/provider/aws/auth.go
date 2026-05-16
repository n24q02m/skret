package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// loadAWSConfig creates an AWS configuration instance. When creds is non-nil
// (a skret-stored credential resolved via resolveStoredCredentials) it is used
// directly and profile is ignored — that is what lets `skret auth login aws`
// authenticate without the `aws` CLI. When creds is nil the standard SDK
// credential chain is used, applying the shared profile if specified. Region
// is always applied when set.
func loadAWSConfig(ctx context.Context, region, profile string, creds aws.CredentialsProvider) (aws.Config, error) {
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
