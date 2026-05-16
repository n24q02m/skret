package aws

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
