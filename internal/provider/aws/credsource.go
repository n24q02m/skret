package aws

import (
	"context"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/n24q02m/skret/internal/auth"
)

// authStoreLoad loads a stored credential for a provider. Overridable in tests.
var authStoreLoad = func(provider string) (*auth.Credential, error) {
	return auth.NewStore().Load(provider)
}

// resolveStoredCredentials builds an AWS credentials provider from a
// skret-stored credential (written by `skret auth login aws ...`) so skret
// authenticates on its own without the `aws` CLI. It returns (provider, true)
// only for a usable static access-key credential; for anything else — no
// credential, expired, profile/sso, or incomplete — it returns (nil, false)
// so the caller falls back to the AWS SDK default chain, leaving existing
// `aws login` / CI-OIDC / profile users completely unaffected.
//
// Phase 1 handles access-key only. profile defers to shared-config (already
// supported via --profile / .skret.yaml); sso is Phase 2.
func resolveStoredCredentials() (aws.CredentialsProvider, bool) {
	cred, err := authStoreLoad("aws")
	if err != nil || cred == nil || cred.IsExpired() {
		return nil, false
	}
	if cred.Method != "access-key" {
		return nil, false
	}
	id := cred.Metadata["access_key_id"]
	if id == "" || cred.Token == "" {
		return nil, false
	}
	return aws.NewCredentialsCache(
		credentials.NewStaticCredentialsProvider(id, cred.Token, cred.Metadata["session_token"]),
	), true
}

// Probe verifies AWS reachability using the SAME credential resolution skret
// uses for real operations (stored credential first, else SDK default chain),
// so `skret auth status` cannot disagree with what `skret list` actually does.
// Region comes from AWS_REGION/SKRET_REGION, falling back to us-east-1 purely
// for the region-agnostic GetCallerIdentity check. Never surfaces secrets.
func Probe(ctx context.Context) error {
	creds, _ := resolveStoredCredentials()
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("SKRET_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := loadAWSConfig(ctx, region, "", creds)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}
