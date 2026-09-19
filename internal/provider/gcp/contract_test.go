package gcp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/n24q02m/skret/internal/provider"
	skgcp "github.com/n24q02m/skret/internal/provider/gcp"
)

func TestProviderName(t *testing.T) {
	assert.Equal(t, "gcp", newProvider(newFakeGCP()).Name())
}

func TestProviderCapabilities(t *testing.T) {
	caps := newProvider(newFakeGCP()).Capabilities()
	assert.True(t, caps.Write)
	assert.True(t, caps.Versioning)
	assert.True(t, caps.Tagging)
	assert.True(t, caps.AuditLog)
	assert.Equal(t, 64, caps.MaxValueKB, "Secret Manager caps payloads at 64 KiB")
}

func TestGet(t *testing.T) {
	t.Run("returns latest value and parsed version", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("API_KEY", 3, nil, nil, nil)
		s, err := newProvider(f).Get(context.Background(), "API_KEY")
		require.NoError(t, err)
		assert.Equal(t, "v3", s.Value)
		assert.Equal(t, int64(3), s.Version)
		assert.Equal(t, "API_KEY", s.Key)
	})

	t.Run("leading slash is tolerated", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("API_KEY", 1, nil, nil, nil)
		s, err := newProvider(f).Get(context.Background(), "/API_KEY")
		require.NoError(t, err)
		assert.Equal(t, "v1", s.Value)
	})

	t.Run("missing key maps to ErrNotFound", func(t *testing.T) {
		_, err := newProvider(newFakeGCP()).Get(context.Background(), "NOPE")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("empty key and nil client map to ErrNotFound", func(t *testing.T) {
		_, err := newProvider(newFakeGCP()).Get(context.Background(), "")
		assert.ErrorIs(t, err, provider.ErrNotFound)
		_, err = skgcp.NewWithClient(nil, testProject, "", "").Get(context.Background(), "K")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("invalid secret id is rejected before any call", func(t *testing.T) {
		f := newFakeGCP()
		_, err := newProvider(f).Get(context.Background(), "app/prod/KEY")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid secret id")
		assert.Empty(t, f.calls, "no API call may be issued for an invalid id")
	})

	t.Run("api error keeps the gcp envelope", func(t *testing.T) {
		f := newFakeGCP()
		f.errAccess = statusErr(codes.PermissionDenied)
		_, err := newProvider(f).Get(context.Background(), "API_KEY")
		require.Error(t, err)
		assert.ErrorContains(t, err, `gcp: get "API_KEY"`)
	})
}

func TestGetVersion(t *testing.T) {
	t.Run("returns the requested immutable version", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 3, nil, nil, nil)
		vr, ok := newProvider(f).(provider.VersionedReader)
		require.True(t, ok, "gcp must satisfy VersionedReader")
		s, err := vr.GetVersion(context.Background(), "K", 1)
		require.NoError(t, err)
		assert.Equal(t, "v1", s.Value)
		assert.Equal(t, int64(1), s.Version)
	})

	t.Run("missing version maps to ErrNotFound", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 3, nil, nil, nil)
		vr := newProvider(f).(provider.VersionedReader)
		_, err := vr.GetVersion(context.Background(), "K", 42)
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("non-positive version maps to ErrNotFound", func(t *testing.T) {
		vr := newProvider(newFakeGCP()).(provider.VersionedReader)
		_, err := vr.GetVersion(context.Background(), "K", 0)
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})
}

func TestGetBatch(t *testing.T) {
	t.Run("preserves input order and skips missing", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("B_KEY", 1, nil, nil, nil)
		f.seed("A_KEY", 2, nil, nil, nil)
		secrets, err := newProvider(f).GetBatch(context.Background(), []string{"B_KEY", "MISSING", "A_KEY"})
		require.NoError(t, err)
		require.Len(t, secrets, 2)
		assert.Equal(t, "B_KEY", secrets[0].Key)
		assert.Equal(t, "A_KEY", secrets[1].Key)
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		secrets, err := newProvider(newFakeGCP()).GetBatch(context.Background(), nil)
		require.NoError(t, err)
		assert.Nil(t, secrets)
	})

	t.Run("non-notfound error fails the batch", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		f.errAccess = statusErr(codes.PermissionDenied)
		_, err := newProvider(f).GetBatch(context.Background(), []string{"K"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "gcp: get")
	})
}

func TestList(t *testing.T) {
	t.Run("empty prefix returns all secrets with values", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("B", 2, nil, nil, timestamppb.New(time.Unix(100, 0)))
		f.seed("A", 1, nil, nil, nil)
		secrets, err := newProvider(f).List(context.Background(), "")
		require.NoError(t, err)
		require.Len(t, secrets, 2)
		byKey := map[string]*provider.Secret{}
		for _, s := range secrets {
			byKey[s.Key] = s
		}
		assert.Equal(t, "v2", byKey["B"].Value)
		assert.True(t, byKey["B"].Meta.CreatedAt.Equal(time.Unix(100, 0)), "CreatedAt comes from secret metadata")
	})

	t.Run("prefix filters on flat ids", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("prod-db", 1, nil, nil, nil)
		f.seed("staging-db", 1, nil, nil, nil)
		secrets, err := newProvider(f).List(context.Background(), "prod-")
		require.NoError(t, err)
		require.Len(t, secrets, 1)
		assert.Equal(t, "prod-db", secrets[0].Key)
	})

	t.Run("secret without readable versions is skipped", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("EMPTY", 0, nil, nil, nil)
		f.seed("OK", 1, nil, nil, nil)
		secrets, err := newProvider(f).List(context.Background(), "")
		require.NoError(t, err)
		require.Len(t, secrets, 1)
		assert.Equal(t, "OK", secrets[0].Key)
	})

	t.Run("api error maps through the envelope", func(t *testing.T) {
		f := newFakeGCP()
		f.errList = statusErr(codes.PermissionDenied)
		_, err := newProvider(f).List(context.Background(), "")
		assert.ErrorContains(t, err, "gcp: list")
	})
}

func TestListNames(t *testing.T) {
	t.Run("names without decrypting", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("prod-a", 1, nil, nil, nil)
		f.seed("prod-b", 1, nil, nil, nil)
		names, err := newProvider(f).ListNames(context.Background(), "prod-")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"prod-a", "prod-b"}, names)
		require.NotContains(t, f.calls, "AccessSecretVersion", "name-only listing must not decrypt")
	})

	t.Run("api error maps through the envelope", func(t *testing.T) {
		f := newFakeGCP()
		f.errList = statusErr(codes.Unavailable)
		_, err := newProvider(f).ListNames(context.Background(), "")
		assert.ErrorContains(t, err, "gcp: list")
	})
}

func TestFingerprint(t *testing.T) {
	t.Run("stable and version-sensitive without decrypting", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("A", 1, nil, nil, nil)
		f.seed("B", 3, nil, nil, nil)
		p := newProvider(f)

		fp1, err := p.Fingerprint(context.Background(), "")
		require.NoError(t, err)
		fp2, err := p.Fingerprint(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, fp1, fp2, "identical state must produce an identical fingerprint")
		assert.NotEmpty(t, fp1)

		f.seedVersions("A", 1) // bump A to version 2
		fp3, err := p.Fingerprint(context.Background(), "")
		require.NoError(t, err)
		assert.NotEqual(t, fp1, fp3, "a new version must change the fingerprint")

		require.NotContains(t, f.calls, "AccessSecretVersion", "fingerprint must not decrypt any value")
	})

	t.Run("prefix scoping", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("prod-a", 1, nil, nil, nil)
		f.seed("staging-a", 1, nil, nil, nil)
		fp, err := newProvider(f).Fingerprint(context.Background(), "prod-")
		require.NoError(t, err)
		assert.NotEmpty(t, fp)
	})

	t.Run("list error maps through the envelope", func(t *testing.T) {
		f := newFakeGCP()
		f.errList = statusErr(codes.PermissionDenied)
		_, err := newProvider(f).Fingerprint(context.Background(), "")
		assert.ErrorContains(t, err, "gcp: fingerprint")
	})

	t.Run("versions error maps through the envelope", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("A", 1, nil, nil, nil)
		f.errListVersions = statusErr(codes.Unavailable)
		_, err := newProvider(f).Fingerprint(context.Background(), "")
		assert.ErrorContains(t, err, "gcp: fingerprint")
	})
}

func TestSetCreateNew(t *testing.T) {
	t.Run("creates secret with mirrored metadata then first version", func(t *testing.T) {
		f := newFakeGCP()
		meta := provider.SecretMeta{
			Description: "db credential",
			Tags:        map[string]string{"team": "core"},
			ExpiresAt:   time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC),
		}
		err := newProvider(f).Set(context.Background(), "DB_URL", "postgres://x", meta)
		require.NoError(t, err)

		require.Len(t, f.createReqs, 1)
		create := f.createReqs[0]
		assert.Equal(t, "DB_URL", create.SecretId)
		assert.Equal(t, "projects/"+testProject, create.Parent)
		assert.Equal(t, map[string]string{"team": "core"}, create.Secret.Labels)
		assert.Equal(t, "db credential", create.Secret.Annotations["skret-description"])
		assert.Equal(t, "2027-01-02T03:04:05Z", create.Secret.Annotations["skret-expires-at"])
		require.NotNil(t, create.Secret.GetReplication().GetAutomatic(), "global secrets use automatic replication")

		require.Len(t, f.addReqs, 1)
		assert.Equal(t, "postgres://x", string(f.addReqs[0].Payload.Data))
		assert.Empty(t, f.updateReqs, "a fresh create must not issue UpdateSecret")
		assert.Equal(t, []string{"GetSecret", "CreateSecret", "AddSecretVersion"}, f.calls, "no pre-version readback on the create path")
	})

	t.Run("regional location switches to user-managed replication", func(t *testing.T) {
		f := newFakeGCP()
		p := skgcp.NewWithClient(f, testProject, "us-east1", "")
		require.NoError(t, p.Set(context.Background(), "K", "v", provider.SecretMeta{}))

		rep := f.createReqs[0].Secret.GetReplication()
		um := rep.GetUserManaged()
		require.NotNil(t, um)
		require.Len(t, um.Replicas, 1)
		assert.Equal(t, "us-east1", um.Replicas[0].Location)
	})

	t.Run("cmek rides the replication policy", func(t *testing.T) {
		f := newFakeGCP()
		p := skgcp.NewWithClient(f, testProject, "", "projects/p/locations/global/keyRings/r/cryptoKeys/k")
		require.NoError(t, p.Set(context.Background(), "K", "v", provider.SecretMeta{}))
		cmek := f.createReqs[0].Secret.GetReplication().GetAutomatic().GetCustomerManagedEncryption()
		require.NotNil(t, cmek)
		assert.Equal(t, "projects/p/locations/global/keyRings/r/cryptoKeys/k", cmek.KmsKeyName)
	})
}

func TestSetExisting(t *testing.T) {
	t.Run("adds a version without touching unchanged metadata", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 2, nil, map[string]string{skgcp.AnnotationDescription: "same"}, nil)
		err := newProvider(f).Set(context.Background(), "K", "v3", provider.SecretMeta{Description: "same"})
		require.NoError(t, err)
		assert.Empty(t, f.updateReqs)
		require.Len(t, f.addReqs, 1)
	})

	t.Run("updates stale annotations and labels", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, map[string]string{"team": "old"}, nil, nil)
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{
			Description: "fresh",
			Tags:        map[string]string{"team": "new"},
		})
		require.NoError(t, err)
		require.Len(t, f.updateReqs, 1)
		upd := f.updateReqs[0]
		assert.Equal(t, map[string]string{"team": "new"}, upd.Secret.Labels)
		assert.Equal(t, "fresh", upd.Secret.Annotations[skgcp.AnnotationDescription])
		assert.ElementsMatch(t, []string{"labels", "annotations"}, upd.UpdateMask.Paths)

		secrets, lerr := newProvider(f).List(context.Background(), "")
		require.NoError(t, lerr)
		require.Len(t, secrets, 1)
		assert.Equal(t, "v2", secrets[0].Value, "value version must be 2 after one bump")
		assert.Equal(t, int64(2), secrets[0].Version)
	})

	t.Run("empty meta clears stale mirrored metadata", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, map[string]string{skgcp.AnnotationExpiresAt: "2020-01-01T00:00:00Z"}, nil)
		require.NoError(t, newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{}))
		require.Len(t, f.updateReqs, 1, "mirrored metadata must be reconciled to empty")
	})
}

func TestSetValidation(t *testing.T) {
	t.Run("oversized value is rejected locally", func(t *testing.T) {
		f := newFakeGCP()
		err := newProvider(f).Set(context.Background(), "K", makeString(64*1024+1), provider.SecretMeta{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "caps payloads at 65536 bytes")
		assert.Empty(t, f.calls)
	})

	t.Run("invalid id is rejected before any call", func(t *testing.T) {
		f := newFakeGCP()
		err := newProvider(f).Set(context.Background(), "bad/name", "v", provider.SecretMeta{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid secret id")
		assert.Empty(t, f.calls)
	})
}

func makeString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestSetPartialCommit(t *testing.T) {
	t.Run("definitive add failure maps straight through", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		f.errAdd = statusErr(codes.InvalidArgument)
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{})
		require.Error(t, err)
		assert.ErrorContains(t, err, `gcp: set "K"`)
		var partial *provider.PartialCommitError
		assert.False(t, errorsAs(err, &partial), "definitive rejections must not report partial commit")
	})

	t.Run("ambiguous add failure with committed version reports partial commit", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		f.errAddLostResponse = true
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{})
		require.Error(t, err)
		var partial *provider.PartialCommitError
		require.True(t, errorsAs(err, &partial))
		assert.Equal(t, int64(2), partial.ObservedVersion)
		assert.Equal(t, int64(1), partial.PreVersion)
		assert.Equal(t, provider.TagReconciliationUnknown, partial.TagState)
		assert.ErrorIs(t, err, provider.ErrPartialCommit)
	})

	t.Run("ambiguous add failure with unchanged version maps through", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		// readback (AccessSecretVersion) succeeds and still sees version 1
		f.errAdd = statusErr(codes.Unavailable)
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{})
		require.Error(t, err)
		var partial *provider.PartialCommitError
		assert.False(t, errorsAs(err, &partial))
		assert.ErrorContains(t, err, `gcp: set "K"`)
	})

	t.Run("ambiguous add failure with failed readback reports unknown commit", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		f.errAdd = statusErr(codes.Unavailable)
		f.errAccessAfterAdds = statusErr(codes.Unavailable)
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{})
		require.Error(t, err)
		var partial *provider.PartialCommitError
		require.True(t, errorsAs(err, &partial))
		assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
	})

	t.Run("failed metadata update after committed value reports tag reconciliation", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, map[string]string{"team": "old"}, nil, nil)
		f.errUpdate = statusErr(codes.PermissionDenied)
		err := newProvider(f).Set(context.Background(), "K", "v2", provider.SecretMeta{Tags: map[string]string{"team": "new"}})
		require.Error(t, err)
		var partial *provider.PartialCommitError
		require.True(t, errorsAs(err, &partial))
		assert.Equal(t, int64(2), partial.Version)
		assert.Equal(t, provider.TagReconciliationRequired, partial.TagState)
	})

	t.Run("ambiguous failure on the create path reports unknown commit", func(t *testing.T) {
		f := newFakeGCP()
		f.errCreate = statusErr(codes.Unavailable)
		err := newProvider(f).Set(context.Background(), "K", "v", provider.SecretMeta{})
		require.Error(t, err)
		var partial *provider.PartialCommitError
		require.True(t, errorsAs(err, &partial))
		assert.Equal(t, provider.MutationCommitUnknown, partial.CommitState)
		assert.Equal(t, int64(0), partial.ObservedVersion)
	})

	t.Run("definitive create failure maps straight through", func(t *testing.T) {
		f := newFakeGCP()
		f.errCreate = statusErr(codes.PermissionDenied)
		err := newProvider(f).Set(context.Background(), "K", "v", provider.SecretMeta{})
		require.Error(t, err)
		assert.ErrorContains(t, err, `gcp: set "K"`)
		var partial *provider.PartialCommitError
		assert.False(t, errorsAs(err, &partial))
	})
}

// errorsAs is a tiny indirection so the assertions above stay readable.
func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}

func TestDelete(t *testing.T) {
	t.Run("deletes an existing secret", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 1, nil, nil, nil)
		require.NoError(t, newProvider(f).Delete(context.Background(), "K"))
		require.Len(t, f.deleteReqs, 1)
		assert.Equal(t, secretPrefix+"K", f.deleteReqs[0].Name)
	})

	t.Run("missing secret maps to ErrNotFound", func(t *testing.T) {
		err := newProvider(newFakeGCP()).Delete(context.Background(), "NOPE")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})

	t.Run("invalid id is rejected before any call", func(t *testing.T) {
		f := newFakeGCP()
		err := newProvider(f).Delete(context.Background(), "a/b")
		require.Error(t, err)
		assert.Empty(t, f.calls)
	})
}

func TestGetHistory(t *testing.T) {
	t.Run("returns enabled versions in ascending order", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 3, nil, nil, nil)
		// a disabled version must be excluded even when the server ignores
		// the state filter
		f.versions[secretPrefix+"K"] = append(f.versions[secretPrefix+"K"], &secretmanagerpb.SecretVersion{
			Name:  secretPrefix + "K/versions/4",
			State: secretmanagerpb.SecretVersion_DISABLED,
		})
		f.payloads[secretPrefix+"K/versions/4"] = "v4"

		history, err := newProvider(f).GetHistory(context.Background(), "K")
		require.NoError(t, err)
		require.Len(t, history, 3)
		assert.Equal(t, int64(1), history[0].Version)
		assert.Equal(t, int64(2), history[1].Version)
		assert.Equal(t, int64(3), history[2].Version)
		assert.Equal(t, "v3", history[2].Value)
		assert.False(t, history[0].Meta.UpdatedAt.IsZero(), "history fills UpdatedAt from version metadata")
	})

	t.Run("version destroyed mid-read drops out of history", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 2, nil, nil, nil)
		f.errAccessForName[secretPrefix+"K/versions/2"] = statusErr(codes.FailedPrecondition)
		history, err := newProvider(f).GetHistory(context.Background(), "K")
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Equal(t, int64(1), history[0].Version)
	})

	t.Run("missing secret maps to ErrNotFound", func(t *testing.T) {
		_, err := newProvider(newFakeGCP()).GetHistory(context.Background(), "NOPE")
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})
}

func TestRollback(t *testing.T) {
	t.Run("re-adds the old value as a new version", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 2, nil, nil, nil)
		require.NoError(t, newProvider(f).Rollback(context.Background(), "K", 1))

		s, err := newProvider(f).Get(context.Background(), "K")
		require.NoError(t, err)
		assert.Equal(t, "v1", s.Value, "rollback must restore the old value")
		assert.Equal(t, int64(3), s.Version, "rollback must land as a fresh immutable version")
	})

	t.Run("unknown version maps to ErrNotFound", func(t *testing.T) {
		f := newFakeGCP()
		f.seed("K", 2, nil, nil, nil)
		err := newProvider(f).Rollback(context.Background(), "K", 99)
		assert.ErrorIs(t, err, provider.ErrNotFound)
	})
}

func TestClose(t *testing.T) {
	assert.NoError(t, newProvider(newFakeGCP()).Close())
}

func TestRegionalResourceNames(t *testing.T) {
	f := newFakeGCP()
	p := skgcp.NewWithClient(f, testProject, "europe-west1", "")
	f.secrets["projects/"+testProject+"/locations/europe-west1/secrets/K"] = &secretmanagerpb.Secret{
		Name: "projects/" + testProject + "/locations/europe-west1/secrets/K",
	}
	f.versions["projects/"+testProject+"/locations/europe-west1/secrets/K"] = []*secretmanagerpb.SecretVersion{{
		Name:  "projects/" + testProject + "/locations/europe-west1/secrets/K/versions/1",
		State: secretmanagerpb.SecretVersion_ENABLED,
	}}
	f.payloads["projects/"+testProject+"/locations/europe-west1/secrets/K/versions/1"] = "regional"

	s, err := p.Get(context.Background(), "K")
	require.NoError(t, err)
	assert.Equal(t, "regional", s.Value)
	assert.True(t, strings.HasPrefix(f.accessReqs[0].Name, "projects/"+testProject+"/locations/europe-west1/secrets/K/versions/"), "regional resource names must carry the location segment")
}

func TestAccessVersionNilPayload(t *testing.T) {
	f := newFakeGCP()
	f.seed("K", 1, nil, nil, nil)
	f.nilPayload = true
	_, err := newProvider(f).Get(context.Background(), "K")
	assert.ErrorIs(t, err, provider.ErrNotFound)
}

func TestProviderCloseWithoutAdapter(t *testing.T) {
	// A client that does not implement Close must still close cleanly.
	p := skgcp.NewWithClient(newFakeGCP(), testProject, "", "")
	assert.NoError(t, p.Close())
}
