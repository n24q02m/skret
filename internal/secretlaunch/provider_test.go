package secretlaunch

import (
	"context"
	"strings"
	"testing"
)

func TestFetchSecretsRequestsExactKeyAndVersionAndZeroizesPriorFetch(t *testing.T) {
	calls := make([]string, 0, 2)
	first := []byte("first-synthetic-sentinel")
	provider := FetchFunc(func(_ context.Context, key, version string) ([]byte, error) {
		calls = append(calls, key+"@"+version)
		if key == "BROKEN" {
			return nil, errSynthetic
		}
		return first, nil
	})
	_, err := FetchSecrets(context.Background(), provider, []ManifestKey{
		{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"},
		{Name: "BROKEN", Version: "2", Env: "BROKEN"},
	})
	if errorCode(err) != ErrFetch || strings.Contains(err.Error(), "synthetic-sentinel") {
		t.Fatalf("fetch error = %v", err)
	}
	if calls[0] != "APP_TOKEN@1" || calls[1] != "BROKEN@2" {
		t.Fatalf("exact provider calls = %v", calls)
	}
	for _, value := range first {
		if value != 0 {
			t.Fatal("prior fetched value was not zeroized")
		}
	}
}

func TestFetchSecretsRejectsDuplicateKeyAndMissingProvider(t *testing.T) {
	keys := []ManifestKey{{Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}, {Name: "APP_TOKEN", Version: "1", Env: "APP_TOKEN"}}
	if _, err := FetchSecrets(context.Background(), FetchFunc(func(context.Context, string, string) ([]byte, error) { return []byte("x"), nil }), keys); errorCode(err) != ErrKey {
		t.Fatalf("duplicate key code = %v", errorCode(err))
	}
	if _, err := FetchSecrets(context.Background(), nil, keys[:1]); errorCode(err) != ErrNoProvider {
		t.Fatalf("missing provider code = %v", errorCode(err))
	}
}

func TestFetchSecretsRejectsNonNumericVersionAndInvalidEnvironment(t *testing.T) {
	provider := FetchFunc(func(context.Context, string, string) ([]byte, error) {
		t.Fatal("invalid manifest key reached provider")
		return nil, nil
	})
	for _, key := range []ManifestKey{
		{Name: "APP_TOKEN", Version: "latest", Env: "APP_TOKEN"},
		{Name: "APP_TOKEN", Version: "1", Env: "BAD-NAME"},
	} {
		if _, err := FetchSecrets(context.Background(), provider, []ManifestKey{key}); errorCode(err) != ErrKey {
			t.Fatalf("invalid key %#v code = %v", key, errorCode(err))
		}
	}
}

type syntheticError string

func (e syntheticError) Error() string { return string(e) }

var errSynthetic = syntheticError("provider failure synthetic-sentinel")
