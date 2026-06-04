package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
)

// Bug H: auth status must reflect a real AWS liveness probe, not just trust
// stored metadata (which made "method: profile" always report "valid").
func TestAuthStatusReflectsProbe(t *testing.T) {
	orig := awsLivenessProbe
	defer func() { awsLivenessProbe = orig }()

	awsLivenessProbe = func(context.Context, *auth.Credential) error {
		return errors.New("ExpiredTokenException: the security token included in the request is expired")
	}
	if got := getCredentialStatus(context.Background(), "aws", &auth.Credential{Method: "profile"}); got != "expired" {
		t.Fatalf("expired probe: got %q want expired", got)
	}

	awsLivenessProbe = func(context.Context, *auth.Credential) error { return errors.New("dial tcp: i/o timeout") }
	if got := getCredentialStatus(context.Background(), "aws", &auth.Credential{Method: "profile"}); got != "unreachable" {
		t.Fatalf("network error: got %q want unreachable", got)
	}

	awsLivenessProbe = func(context.Context, *auth.Credential) error { return nil }
	if got := getCredentialStatus(context.Background(), "aws", &auth.Credential{Method: "profile"}); got != "valid" {
		t.Fatalf("ok probe: got %q want valid", got)
	}
}

func TestGetCredentialStatus_OtherProviderInvalid(t *testing.T) {
	// Coverage for non-aws provider with invalid credentials
	cred := &auth.Credential{Method: "token"}
	got := getCredentialStatus(context.Background(), "doppler", cred)
	// Resolution will fail because no real doppler backend is mocked here
	assert.Equal(t, "invalid", got)
}
