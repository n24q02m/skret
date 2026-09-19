package gcp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSecretID(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantID  string
		wantErr bool
	}{
		{name: "plain leaf", key: "DB_PASSWORD", wantID: "DB_PASSWORD"},
		{name: "dashes and underscores", key: "prod_DB-key1", wantID: "prod_DB-key1"},
		{name: "leading slash tolerated", key: "/DB_PASSWORD", wantID: "DB_PASSWORD"},
		{name: "empty", key: "", wantErr: true},
		{name: "path separator", key: "app/prod/KEY", wantErr: true},
		{name: "dot", key: "db.url", wantErr: true},
		{name: "space", key: "db url", wantErr: true},
		{name: "unicode", key: "秘钥", wantErr: true},
		{name: "over 255 chars", key: strings.Repeat("a", 256), wantErr: true},
		{name: "exactly 255 chars", key: strings.Repeat("a", 255), wantID: strings.Repeat("a", 255)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := secretID("op", tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid secret id")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestVersionNumberOf(t *testing.T) {
	assert.Equal(t, int64(3), versionNumberOf("projects/p/secrets/s/versions/3"))
	assert.Equal(t, int64(0), versionNumberOf("projects/p/secrets/s"))
	assert.Equal(t, int64(0), versionNumberOf("projects/p/secrets/s/versions/abc"))
}

func TestSecretNameID(t *testing.T) {
	assert.Equal(t, "s", secretNameID("projects/p/secrets/s"))
	assert.Equal(t, "s", secretNameID("projects/p/locations/l/secrets/s"))
	assert.Equal(t, "bare", secretNameID("bare"))
}

func TestListPrefix(t *testing.T) {
	assert.Equal(t, "", listPrefix(""))
	assert.Equal(t, "prod-", listPrefix("/prod-"))
	assert.Equal(t, "prod-", listPrefix("prod-"))
}

func TestAnnotationsFromMeta(t *testing.T) {
	expires := time.Date(2027, 3, 4, 5, 6, 7, 0, time.UTC)
	got := annotationsFromMeta(provider.SecretMeta{
		Description: "desc",
		ExpiresAt:   expires,
	})
	assert.Equal(t, map[string]string{
		AnnotationDescription: "desc",
		AnnotationExpiresAt:   "2027-03-04T05:06:07Z",
	}, got)

	assert.Empty(t, annotationsFromMeta(provider.SecretMeta{}), "empty meta yields no annotations")
}

func TestLabelsFromMeta(t *testing.T) {
	assert.Nil(t, labelsFromMeta(provider.SecretMeta{}))
	got := labelsFromMeta(provider.SecretMeta{Tags: map[string]string{"team": "core"}})
	assert.Equal(t, map[string]string{"team": "core"}, got)
}

func TestEqualStringMaps(t *testing.T) {
	assert.True(t, equalStringMaps(nil, nil))
	assert.True(t, equalStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "1"}))
	assert.False(t, equalStringMaps(map[string]string{"a": "1"}, nil))
	assert.False(t, equalStringMaps(map[string]string{"a": "1"}, map[string]string{"a": "2"}))
	assert.False(t, equalStringMaps(map[string]string{"a": "1"}, map[string]string{"b": "1"}))
}

func TestHashLinesOrderIndependent(t *testing.T) {
	a := hashLines([]string{"x@1", "y@2"})
	b := hashLines([]string{"y@2", "x@1"})
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, hashLines([]string{"x@1"}))
}

func TestRegionalEndpoint(t *testing.T) {
	assert.Equal(t, "secretmanager.us-east1.rep.googleapis.com:443", regionalEndpoint("us-east1"))
}

func TestMapError(t *testing.T) {
	err := mapError("get", "K", status.Error(codes.NotFound, "gone"))
	assert.ErrorIs(t, err, provider.ErrNotFound)
	assert.Nil(t, mapError("get", "K", nil), "nil stays nil")

	plain := errors.New("boom")
	wrapped := mapError("get", "K", plain)
	assert.ErrorContains(t, wrapped, `gcp: get "K"`)
	assert.ErrorIs(t, wrapped, plain)
}

func TestErrorIsDefinitive(t *testing.T) {
	definitive := []codes.Code{
		codes.InvalidArgument,
		codes.NotFound,
		codes.PermissionDenied,
		codes.AlreadyExists,
		codes.FailedPrecondition,
		codes.Unauthenticated,
		codes.OutOfRange,
	}
	for _, c := range definitive {
		assert.True(t, errorIsDefinitive(status.Error(c, "x")), c.String())
	}
	ambiguous := []codes.Code{
		codes.Unavailable,
		codes.DeadlineExceeded,
		codes.Internal,
		codes.Canceled,
		codes.ResourceExhausted,
		codes.Unknown,
		codes.DataLoss,
		codes.Aborted,
		codes.Unimplemented,
	}
	for _, c := range ambiguous {
		assert.False(t, errorIsDefinitive(status.Error(c, "x")), c.String())
	}
	assert.False(t, errorIsDefinitive(errors.New("non-status")), "non-status errors must reconcile")
}

func TestStatusCodeOnPlainError(t *testing.T) {
	assert.Equal(t, codes.OK, statusCode(errors.New("plain")))
}

func TestHighestEnabledVersion(t *testing.T) {
	mk := func(name string, state secretmanagerpb.SecretVersion_State) *secretmanagerpb.SecretVersion {
		return &secretmanagerpb.SecretVersion{Name: name, State: state}
	}
	enabled := "projects/p/secrets/s/versions/2"
	disabled := "projects/p/secrets/s/versions/3"
	assert.Equal(t, int64(2), highestEnabledVersion([]*secretmanagerpb.SecretVersion{
		mk("projects/p/secrets/s/versions/1", secretmanagerpb.SecretVersion_ENABLED),
		mk(enabled, secretmanagerpb.SecretVersion_ENABLED),
		mk(disabled, secretmanagerpb.SecretVersion_DISABLED),
	}))
	assert.Equal(t, int64(0), highestEnabledVersion([]*secretmanagerpb.SecretVersion{
		mk(disabled, secretmanagerpb.SecretVersion_DISABLED),
	}))
	assert.Equal(t, int64(0), highestEnabledVersion(nil))
}
