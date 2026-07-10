package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	bsSecret  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	bsKeyID   = "AKIAIOSFODNN7EXAMPLE"
	bsAccount = "123456789012"
)

// bsFakeIAM is a minimal IAM client: the user always exists and a key mint
// returns the fixed test key id + secret.
type bsFakeIAM struct{ calls int }

func (f *bsFakeIAM) GetUser(_ context.Context, _ *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return &iam.GetUserOutput{}, nil
}

func (f *bsFakeIAM) CreateUser(_ context.Context, _ *iam.CreateUserInput, _ ...func(*iam.Options)) (*iam.CreateUserOutput, error) {
	return &iam.CreateUserOutput{}, nil
}

func (f *bsFakeIAM) PutUserPolicy(_ context.Context, _ *iam.PutUserPolicyInput, _ ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error) {
	return &iam.PutUserPolicyOutput{}, nil
}

func (f *bsFakeIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}

func (f *bsFakeIAM) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	f.calls++
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId:     aws.String(bsKeyID),
		SecretAccessKey: aws.String(bsSecret),
	}}, nil
}

// bsFailingIAM behaves like bsFakeIAM but fails when minting the access key, so
// Provision returns an error after the identity/user/policy steps.
type bsFailingIAM struct{ bsFakeIAM }

func (f *bsFailingIAM) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return nil, errors.New("limit exceeded")
}

type bsFakeSTS struct{}

func (bsFakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(bsAccount)}, nil
}

// withFakeBootstrap swaps the package seams for the duration of a test, pointing
// the store at an isolated temp file and the clients at the provided fakes.
func withFakeBootstrap(t *testing.T, iamc auth.IAMClient, stsc auth.STSClient) *auth.Store {
	t.Helper()
	store := auth.NewStoreWithPath(filepath.Join(t.TempDir(), "creds.yaml"))

	origClients := newBootstrapClients
	origStore := bootstrapStore
	t.Cleanup(func() {
		newBootstrapClients = origClients
		bootstrapStore = origStore
	})
	newBootstrapClients = func(context.Context, string, string) (auth.IAMClient, auth.STSClient, error) {
		return iamc, stsc, nil
	}
	bootstrapStore = func() *auth.Store { return store }
	return store
}

func TestBootstrapCmd_Provisions_StoresKey(t *testing.T) {
	store := withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "access-key", cred.Method)
	assert.Equal(t, bsKeyID, cred.Metadata["access_key_id"])
	assert.Equal(t, bsSecret, cred.Token)

	s := out.String()
	assert.Contains(t, s, "skret-myapp")
	assert.Contains(t, s, bsAccount)
	assert.Contains(t, s, bsKeyID)
	assert.Equal(t, 1, strings.Count(s, bsSecret), "secret must appear exactly once in stdout")
}

func TestBootstrapCmd_PrintOnly_DoesNotStore(t *testing.T) {
	store := withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--print-only", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	_, err := store.Load("aws")
	assert.ErrorIs(t, err, auth.ErrCredentialNotFound)

	s := out.String()
	assert.Equal(t, 1, strings.Count(s, bsSecret), "secret must still be printed exactly once")
}

func TestBootstrapCmd_NonInteractive_NoYes_Errors(t *testing.T) {
	iamFake := &bsFakeIAM{}
	store := auth.NewStoreWithPath(filepath.Join(t.TempDir(), "creds.yaml"))

	origClients := newBootstrapClients
	origStore := bootstrapStore
	origTTY := isInteractiveStdin
	t.Cleanup(func() {
		newBootstrapClients = origClients
		bootstrapStore = origStore
		isInteractiveStdin = origTTY
	})
	clientCalls := 0
	newBootstrapClients = func(context.Context, string, string) (auth.IAMClient, auth.STSClient, error) {
		clientCalls++
		return iamFake, bsFakeSTS{}, nil
	}
	bootstrapStore = func() *auth.Store { return store }
	isInteractiveStdin = func() bool { return false }

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitValidationError, se.Code)
	assert.Equal(t, 0, clientCalls, "no client built when confirmation gate not satisfied")
	assert.Equal(t, 0, iamFake.calls, "Provision must not be called")
}

func TestBootstrapCmd_AlreadyStored_NoForce(t *testing.T) {
	iamFake := &bsFakeIAM{}
	store := withFakeBootstrap(t, iamFake, bsFakeSTS{})
	require.NoError(t, store.Save(&auth.Credential{
		Provider: "aws", Method: "access-key", Token: "preexisting",
		Metadata: map[string]string{"access_key_id": "AKIAPREEXISTING00000"},
	}))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, out.String(), "already stored")
	assert.Equal(t, 0, iamFake.calls, "Provision must not be called when a credential already exists")

	// Pre-existing credential is untouched.
	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, "preexisting", cred.Token)
}

func TestBootstrapCmd_ResolvesConfig_DefaultsProjectFromPath(t *testing.T) {
	store := withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"),
		[]byte("version: \"1\"\ndefault_env: prod\nenvironments:\n  prod:\n    provider: aws\n    path: /demo/prod\n    region: ap-southeast-1\n"),
		0o600))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	// No --project/--path/--region: all come from .skret.yaml; project defaults
	// to the path's last segment ("prod") -> user skret-prod.
	cmd.SetArgs([]string{"bootstrap", "--yes"})
	require.NoError(t, cmd.Execute())

	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, bsKeyID, cred.Metadata["access_key_id"])

	s := out.String()
	assert.Contains(t, s, "skret-prod")
	assert.Contains(t, s, "/demo/prod")
}

func TestBootstrapCmd_NoPath_Errors(t *testing.T) {
	withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	dir := t.TempDir() // no .skret.yaml and no --path
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--yes"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitValidationError, se.Code)
}

func TestBootstrapCmd_Force_OverwritesExisting(t *testing.T) {
	iamFake := &bsFakeIAM{}
	store := withFakeBootstrap(t, iamFake, bsFakeSTS{})
	require.NoError(t, store.Save(&auth.Credential{
		Provider: "aws", Method: "access-key", Token: "preexisting",
		Metadata: map[string]string{"access_key_id": "AKIAPREEXISTING00000"},
	}))

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--force", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, 1, iamFake.calls, "Provision runs despite an existing credential when --force is set")
	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, bsSecret, cred.Token, "credential replaced by the freshly minted key")
}

func TestBootstrapCmd_ClientBuildError(t *testing.T) {
	store := auth.NewStoreWithPath(filepath.Join(t.TempDir(), "creds.yaml"))
	origClients := newBootstrapClients
	origStore := bootstrapStore
	t.Cleanup(func() {
		newBootstrapClients = origClients
		bootstrapStore = origStore
	})
	newBootstrapClients = func(context.Context, string, string) (auth.IAMClient, auth.STSClient, error) {
		return nil, nil, errors.New("no credentials")
	}
	bootstrapStore = func() *auth.Store { return store }

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitAuthError, se.Code)
}

func TestBootstrapCmd_ProvisionError(t *testing.T) {
	store := withFakeBootstrap(t, &bsFailingIAM{}, bsFakeSTS{})

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitProviderError, se.Code)

	_, lerr := store.Load("aws")
	assert.ErrorIs(t, lerr, auth.ErrCredentialNotFound, "nothing stored on provisioning failure")
}

func TestBootstrapCmd_StoreError(t *testing.T) {
	// Point the store at a path whose parent is a regular file so MkdirAll fails.
	parent := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(parent, []byte("x"), 0o600))
	store := auth.NewStoreWithPath(filepath.Join(parent, "creds.yaml"))

	origClients := newBootstrapClients
	origStore := bootstrapStore
	t.Cleanup(func() {
		newBootstrapClients = origClients
		bootstrapStore = origStore
	})
	newBootstrapClients = func(context.Context, string, string) (auth.IAMClient, auth.STSClient, error) {
		return &bsFakeIAM{}, bsFakeSTS{}, nil
	}
	bootstrapStore = func() *auth.Store { return store }

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	err := cmd.Execute()
	require.Error(t, err)

	var se *skret.Error
	require.True(t, errors.As(err, &se))
	assert.Equal(t, skret.ExitConfigError, se.Code)
	assert.NotContains(t, err.Error(), bsSecret, "secret must never appear in an error")
}

func TestBootstrapCmd_MalformedConfig_FallsBackToFlags(t *testing.T) {
	// A malformed .skret.yaml makes resolveBootstrapConfig error; the command's
	// own --path/--region flags still drive the run.
	store := withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".skret.yaml"), []byte("::not yaml::\n  - ["), 0o600))
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	require.NoError(t, cmd.Execute())

	cred, err := store.Load("aws")
	require.NoError(t, err)
	assert.Equal(t, bsKeyID, cred.Metadata["access_key_id"])
}

// TestBootstrapCmd_ExplicitConfigMissing_HardError covers bootstrap.go:77-79:
// with --path/--region/--profile all unset (forcing config resolution) and
// an explicit --config pointing at a file that does not exist,
// resolveBootstrapConfig's error must be surfaced as a hard ExitConfigError
// rather than the soft fallback that applies when --config was not set.
func TestBootstrapCmd_ExplicitConfigMissing_HardError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"bootstrap", "--yes", "--config", missing})
	err := cmd.Execute()
	require.Error(t, err)

	assert.Equal(t, skret.ExitConfigError, skret.ExitCode(err))
	assert.Contains(t, err.Error(), "bootstrap: load config failed")
}

func TestSanitizeProject(t *testing.T) {
	assert.Equal(t, "prod", sanitizeProject("/myapp/prod"))
	assert.Equal(t, "prod", sanitizeProject("/myapp/prod/"))
	assert.Equal(t, "demoenv", sanitizeProject("/demo/demo.env!"))
	// A path with no name characters falls back to filepath.Base.
	assert.Equal(t, filepath.Base("/"), sanitizeProject("/"))
}

// TestBootstrapCmd_ValueSafety asserts the secret never appears in an error and
// appears exactly once in stdout.
func TestBootstrapCmd_ValueSafety(t *testing.T) {
	withFakeBootstrap(t, &bsFakeIAM{}, bsFakeSTS{})

	var out bytes.Buffer
	cmd := NewRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"bootstrap", "--yes", "--project", "myapp", "--path", "/myapp/prod", "--region", "ap-southeast-1"})
	err := cmd.Execute()
	require.NoError(t, err)

	assert.Equal(t, 1, strings.Count(out.String(), bsSecret))
}
