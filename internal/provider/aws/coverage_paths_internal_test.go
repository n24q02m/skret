package aws

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/provider"
)

// testSharedProfile is defined only in the isolated shared config file that
// isolateAWSConfig writes; testMissingProfile is defined nowhere.
const (
	testSharedProfile  = "skret-coverage-profile"
	testSharedRegion   = "eu-north-1"
	testMissingProfile = "skret-coverage-missing-profile"
)

// isolateAWSConfig points the SDK at a temp shared config holding one known
// profile and clears every ambient AWS selector, so these tests never read the
// developer's ~/.aws files or reach a credential endpoint.
func isolateAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config")
	credentialsFile := filepath.Join(dir, "credentials")
	require.NoError(t, os.WriteFile(configFile,
		[]byte("[profile "+testSharedProfile+"]\nregion = "+testSharedRegion+"\n"), 0o600))
	require.NoError(t, os.WriteFile(credentialsFile, nil, 0o600))
	t.Setenv("AWS_CONFIG_FILE", configFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credentialsFile)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// stubStoredCredential replaces the skret credential store lookup for one test.
func stubStoredCredential(t *testing.T, cred *auth.Credential) {
	t.Helper()
	orig := authStoreLoad
	authStoreLoad = func(string) (*auth.Credential, error) { return cred, nil }
	t.Cleanup(func() { authStoreLoad = orig })
}

// The CloudTrail client must resolve credentials exactly like the SSM
// provider: with no profile in the project config, the profile stored by
// `skret auth login aws --method profile` is applied.
func TestNewCloudTrailLookuperFallsBackToStoredProfile(t *testing.T) {
	isolateAWSConfig(t)
	stubStoredCredential(t, &auth.Credential{
		Method:   "profile",
		Metadata: map[string]string{"profile": testSharedProfile},
	})

	lookuper, err := NewCloudTrailLookuper(&config.ResolvedConfig{})
	require.NoError(t, err)
	client, ok := lookuper.(*cloudtrail.Client)
	require.True(t, ok, "lookuper must be the SDK CloudTrail client")
	assert.Equal(t, testSharedRegion, client.Options().Region,
		"the stored profile's region must reach the CloudTrail client")
}

// A profile that the shared config does not define is a configuration error
// the audit command must surface, wrapped with the cloudtrail context.
func TestNewCloudTrailLookuperReportsMissingProfile(t *testing.T) {
	isolateAWSConfig(t)
	stubStoredCredential(t, nil)

	_, err := NewCloudTrailLookuper(&config.ResolvedConfig{Region: "us-east-1", Profile: testMissingProfile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws: load config for cloudtrail")
	var notExist awsconfig.SharedConfigProfileNotExistError
	assert.ErrorAs(t, err, &notExist)
	assert.Equal(t, testMissingProfile, notExist.Profile)
}

// loadAWSConfig applies a shared profile when no stored credential is given,
// and wraps the SDK error when that profile does not exist.
func TestLoadAWSConfigSharedProfile(t *testing.T) {
	isolateAWSConfig(t)

	cfg, err := loadAWSConfig(context.Background(), "", testSharedProfile, nil)
	require.NoError(t, err)
	assert.Equal(t, testSharedRegion, cfg.Region)

	_, err = loadAWSConfig(context.Background(), "us-east-1", testMissingProfile, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws: load default config")
	var notExist awsconfig.SharedConfigProfileNotExistError
	assert.ErrorAs(t, err, &notExist)
}

// New fails fast (no client is built) when the configured profile is unknown.
func TestNewReportsMissingProfile(t *testing.T) {
	isolateAWSConfig(t)
	stubStoredCredential(t, nil)

	p, err := New(&config.ResolvedConfig{Region: "us-east-1", Profile: testMissingProfile})
	require.Error(t, err)
	assert.Nil(t, p)
	assert.Contains(t, err.Error(), "aws: load default config")
}

// Probe returns the config error for a stored profile that no longer exists
// and never reaches STS.
func TestProbeReportsMissingStoredProfile(t *testing.T) {
	isolateAWSConfig(t)
	stubStoredCredential(t, &auth.Credential{
		Method:   "profile",
		Metadata: map[string]string{"profile": testMissingProfile},
	})
	origSTS := newSTSClient
	t.Cleanup(func() { newSTSClient = origSTS })
	stsCalled := false
	newSTSClient = func(aws.Config) STSClient {
		stsCalled = true
		return &mockSTSClient{out: &sts.GetCallerIdentityOutput{}}
	}

	err := Probe(context.Background())
	require.Error(t, err)
	var notExist awsconfig.SharedConfigProfileNotExistError
	assert.ErrorAs(t, err, &notExist)
	assert.False(t, stsCalled, "STS must not be called without a usable config")
}

// The default STS factory builds the SDK client from the given config.
func TestDefaultSTSClientFactory(t *testing.T) {
	client := newSTSClient(aws.Config{Region: "ap-southeast-1"})
	stsClient, ok := client.(*sts.Client)
	require.True(t, ok)
	assert.Equal(t, "ap-southeast-1", stsClient.Options().Region)
}

// The default SSO factories surface an unusable ambient AWS config instead of
// building a client, and Retrieve wraps that error before any network call or
// credential persistence.
func TestSSODefaultFactoriesReportConfigErrors(t *testing.T) {
	isolateAWSConfig(t)
	t.Setenv("AWS_PROFILE", testMissingProfile)
	origSave := ssoStoreSave
	t.Cleanup(func() { ssoStoreSave = origSave })
	saved := 0
	ssoStoreSave = func(*auth.Credential) error { saved++; return nil }

	_, err := newSSORefresher("us-east-1")
	assert.Error(t, err)
	_, err = newSSORoleFetcher("us-east-1")
	assert.Error(t, err)

	expired := &ssoProvider{cred: ssoCred(time.Now().Add(-time.Minute))}
	_, err = expired.Retrieve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws sso: build refresher")

	valid := &ssoProvider{cred: ssoCred(time.Now().Add(time.Hour))}
	_, err = valid.Retrieve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws sso: build role fetcher")
	assert.Zero(t, saved, "nothing may be persisted when no client could be built")
}

// Entries without an event ID are dropped both by the sweep and by the
// renderer, so an unidentifiable event never reaches the output.
func TestLookupParameterEventsDropsEventsWithoutID(t *testing.T) {
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	good := ctEvent("id-good", at, "GetParameter", "/app/prod/KEY", "alice", "1.2.3.4")
	noID := ctEvent("ignored", at, "GetParameter", "/app/prod/KEY", "mallory", "9.9.9.9")
	noID.EventId = nil
	emptyID := ctEvent("", at, "GetParameter", "/app/prod/KEY", "mallory", "9.9.9.9")

	events, err := LookupParameterEvents(context.Background(),
		&fakeLookuper{pages: []cloudtrailtypes.Event{noID, emptyID, good}}, AuditLookupOpts{})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "id-good", events[0].EventID)

	_, ok := renderAuditEvent(noID)
	assert.False(t, ok)
}

// Events sharing a timestamp are ordered by event ID so the output is stable.
func TestLookupParameterEventsOrdersTiesByEventID(t *testing.T) {
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	lookuper := &fakeLookuper{pages: []cloudtrailtypes.Event{
		ctEvent("id-c", at, "GetParameter", "/app/prod/KEY", "carol", "1.1.1.1"),
		ctEvent("id-a", at, "GetParameter", "/app/prod/KEY", "alice", "1.1.1.1"),
		ctEvent("id-b", at, "GetParameter", "/app/prod/KEY", "bob", "1.1.1.1"),
	}}

	events, err := LookupParameterEvents(context.Background(), lookuper, AuditLookupOpts{})
	require.NoError(t, err)
	require.Len(t, events, 3)
	assert.Equal(t, []string{"id-a", "id-b", "id-c"},
		[]string{events[0].EventID, events[1].EventID, events[2].EventID})
}

// parameterFromARNs skips resources without a name and keeps looking for the
// first parameter ARN.
func TestParameterFromARNsSkipsUnnamedResources(t *testing.T) {
	name := "arn:aws:ssm:us-east-1:123456789012:parameter/app/prod/KEY"
	other := "arn:aws:kms:us-east-1:123456789012:key/abc"
	got := parameterFromARNs([]cloudtrailtypes.Resource{
		{ResourceName: nil},
		{ResourceName: &other},
		{ResourceName: &name},
	})
	assert.Equal(t, "app/prod/KEY", got)
	assert.Empty(t, parameterFromARNs([]cloudtrailtypes.Resource{{ResourceName: nil}}))
}

// actorFromARN keeps the most specific tail of an identity ARN: the part after
// the last slash, else after the last colon, else the input as is.
func TestActorFromARNShapes(t *testing.T) {
	assert.Empty(t, actorFromARN(""))
	assert.Equal(t, "session-1", actorFromARN("arn:aws:sts::123456789012:assumed-role/deploy/session-1"))
	assert.Equal(t, "root", actorFromARN("arn:aws:iam::123456789012:root"))
	assert.Equal(t, "local-user", actorFromARN("local-user"))
}

// An event without userName and without an identity ARN renders with an empty
// username rather than a made-up actor.
func TestRenderAuditEventWithoutIdentity(t *testing.T) {
	id := "id-anon"
	at := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	envelope := `{"eventSource":"ssm.amazonaws.com","eventName":"GetParameter","requestParameters":{"name":"/app/prod/KEY"}}`
	out, ok := renderAuditEvent(cloudtrailtypes.Event{EventId: &id, EventTime: &at, CloudTrailEvent: &envelope})
	require.True(t, ok)
	assert.Empty(t, out.Username)
	assert.Equal(t, "/app/prod/KEY", out.Parameter)
}

// The version cache ignores entries that cannot be keyed.
func TestVersionCachePutIgnoresUnkeyedSecrets(t *testing.T) {
	cache := newVersionCache()
	cache.put(nil)
	cache.put(&provider.Secret{Key: "", Value: "unkeyed"})
	assert.Empty(t, cache.items)
}

// equalTags treats tag lists of different length, and an observed list with a
// duplicated key, as a mismatch.
func TestEqualTagsRejectsLengthMismatchAndDuplicates(t *testing.T) {
	tag := func(k, v string) ssmtypes.Tag { return ssmtypes.Tag{Key: aws.String(k), Value: aws.String(v)} }

	assert.False(t, equalTags([]ssmtypes.Tag{tag("env", "prod")}, []ssmtypes.Tag{tag("env", "prod"), tag("team", "core")}))
	assert.False(t, equalTags(
		[]ssmtypes.Tag{tag("env", "prod"), tag("env", "prod")},
		[]ssmtypes.Tag{tag("env", "prod"), tag("team", "core")},
	))
	assert.True(t, equalTags(
		[]ssmtypes.Tag{tag("team", "core"), tag("env", "prod")},
		[]ssmtypes.Tag{tag("env", "prod"), tag("team", "core")},
	))
}
