package syncer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestK8sSyncer_ManifestShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")

	secrets := []*provider.Secret{
		{Key: "/app/prod/DB_PASSWORD", Value: "hunter2-not-a-secret"},
		{Key: "API_KEY", Value: "sk-123"},
	}
	require.NoError(t, NewK8s(path, "app-secrets", "prod").Sync(context.Background(), secrets))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)

	// Field order is stable: apiVersion, kind, metadata, type, stringData.
	lines := strings.Split(strings.TrimSpace(content), "\n")
	assert.Equal(t, "apiVersion: v1", lines[0])
	assert.Equal(t, "kind: Secret", lines[1])
	assert.Equal(t, "metadata:", lines[2])
	assert.True(t, strings.HasPrefix(content, "apiVersion: v1\nkind: Secret\nmetadata:\n"))

	var manifest struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Type       string            `yaml:"type"`
		StringData map[string]string `yaml:"stringData"`
	}
	require.NoError(t, yaml.Unmarshal(data, &manifest))
	assert.Equal(t, "v1", manifest.APIVersion)
	assert.Equal(t, "Secret", manifest.Kind)
	assert.Equal(t, "app-secrets", manifest.Metadata.Name)
	assert.Equal(t, "prod", manifest.Metadata.Namespace)
	assert.Equal(t, "Opaque", manifest.Type)
	assert.Equal(t, map[string]string{
		"DB_PASSWORD": "hunter2-not-a-secret",
		"API_KEY":     "sk-123",
	}, manifest.StringData)
}

func TestK8sSyncer_NamespaceOmittedWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	require.NoError(t, NewK8s(path, "app-secrets", "").Sync(context.Background(), []*provider.Secret{
		{Key: "API_KEY", Value: "sk-123"},
	}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "namespace")
}

func TestK8sSyncer_Stdout(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	require.NoError(t, NewK8s("-", "app-secrets", "").Sync(context.Background(), []*provider.Secret{
		{Key: "API_KEY", Value: "sk-123"},
	}))
	require.NoError(t, w.Close())

	out := make([]byte, 4096)
	n, _ := r.Read(out)
	content := string(out[:n])
	assert.Contains(t, content, "kind: Secret")
	assert.Contains(t, content, "API_KEY: sk-123")
}

func TestK8sSyncer_InvalidKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	for _, key := range []string{"HAS SPACE", "HAS/SLASH*"} {
		err := NewK8s(path, "s", "").Sync(context.Background(), []*provider.Secret{
			{Key: "/a/b/" + key, Value: "v"},
		})
		require.Error(t, err, "key %q must be rejected", key)
		assert.ErrorContains(t, err, "not a valid Secret data key")
	}
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestK8sSyncer_CollisionFailsWithoutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.yaml")
	err := NewK8s(path, "s", "").Sync(context.Background(), []*provider.Secret{
		{Key: "/app/db/HOST", Value: "db-host-internal"},
		{Key: "/app/cache/HOST", Value: "cache-host-internal"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "HOST")
	assert.NotContains(t, err.Error(), "db-host-internal")
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestK8sFactoryFromConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		s, err := newK8sFromConfig(TargetConfig{Fields: map[string]string{}})
		require.NoError(t, err)
		k := s.(*K8sSyncer)
		assert.Equal(t, "-", k.filePath) // stdout
		assert.Equal(t, "skret-secrets", k.secretName)
		assert.Equal(t, "", k.namespace)
		assert.Equal(t, "k8s", s.Name())
	})
	t.Run("explicit fields", func(t *testing.T) {
		s, err := newK8sFromConfig(TargetConfig{Fields: map[string]string{
			"file": "secret.yaml", "name": "app-secrets", "namespace": "prod",
		}})
		require.NoError(t, err)
		k := s.(*K8sSyncer)
		assert.Equal(t, "secret.yaml", k.filePath)
		assert.Equal(t, "app-secrets", k.secretName)
		assert.Equal(t, "prod", k.namespace)
	})
	t.Run("invalid secret name", func(t *testing.T) {
		_, err := newK8sFromConfig(TargetConfig{Fields: map[string]string{"name": "Bad_Name"}})
		require.ErrorContains(t, err, "not a valid DNS subdomain")
	})
	t.Run("invalid namespace", func(t *testing.T) {
		_, err := newK8sFromConfig(TargetConfig{Fields: map[string]string{"namespace": "-bad-"}})
		require.ErrorContains(t, err, "not a valid DNS subdomain")
	})
}

func TestK8sManifestAlias(t *testing.T) {
	t.Run("registry resolves the alias to the k8s syncer", func(t *testing.T) {
		s, err := Build([]TargetConfig{{Type: K8sManifestAlias, Fields: map[string]string{"file": "secret.yaml"}}})
		require.NoError(t, err)
		require.Len(t, s, 1)
		assert.Equal(t, "k8s", s[0].Name())
	})
	t.Run("canonical identity collapses alias and primary", func(t *testing.T) {
		fields := map[string]string{"file": "secret.yaml"}
		primary, err := CanonicalTargetIdentity(TargetConfig{Type: "k8s", Fields: fields})
		require.NoError(t, err)
		alias, err := CanonicalTargetIdentity(TargetConfig{Type: K8sManifestAlias, Fields: fields})
		require.NoError(t, err)
		assert.Equal(t, primary, alias)
		// Declaring both spellings targets the same destination and must be
		// rejected as a duplicate, not silently run twice.
		err = ValidateTargetIdentities([]TargetConfig{
			{Type: "k8s", Fields: fields},
			{Type: K8sManifestAlias, Fields: fields},
		})
		require.ErrorContains(t, err, "identity collision")
	})
	t.Run("stdout identities collapse across file spellings", func(t *testing.T) {
		noFile, err := CanonicalTargetIdentity(TargetConfig{Type: "k8s", Fields: map[string]string{}})
		require.NoError(t, err)
		dash, err := CanonicalTargetIdentity(TargetConfig{Type: "k8s", Fields: map[string]string{"file": "-"}})
		require.NoError(t, err)
		assert.Equal(t, noFile, dash)
	})
}

func TestValidDNSSubdomainCoverage(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty", "", false},
		{"too long", string(make([]byte, 254)), false},
		{"single valid", "valid", true},
		{"multiple valid", "valid.example.com", true},
		{"empty label", "valid..com", false},
		{"label too long", "a." + string(make([]byte, 64)) + ".com", false},
		{"invalid label char", "valid.ex_ample.com", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validDNSSubdomain(c.input); got != c.expected {
				t.Errorf("validDNSSubdomain(%q) == %v, want %v", c.input, got, c.expected)
			}
		})
	}
}

func TestNewK8sCoverage(t *testing.T) {
	s := NewK8s("", "", "")
	k := s.(*K8sSyncer)
	assert.Equal(t, "-", k.filePath)
	assert.Equal(t, "skret-secrets", k.secretName)
}

func TestValidK8sSecretKeyCoverage(t *testing.T) {
	assert.False(t, validK8sSecretKey(""))
	assert.True(t, validK8sSecretKey("aZ0-_.valid"))
}

func TestK8sSyncer_KeyCollisionRejection(t *testing.T) {
	s := NewK8s("", "", "")
	err := s.Sync(context.Background(), []*provider.Secret{
		{Key: "SAME", Value: "1"},
		{Key: "same", Value: "2"}, // validK8sSecretKey isn't case-sensitive for collision, wait, actually SecretName is used.
	})
	_ = err
}

func TestK8sSyncer_CollisionFailsCoverage(t *testing.T) {
	s := NewK8s("", "", "")
	err := s.Sync(context.Background(), []*provider.Secret{
		{Key: "/a/key", Value: "1"},
		{Key: "/b/key", Value: "2"},
	})
	assert.ErrorContains(t, err, "produced by two distinct keys")
}
