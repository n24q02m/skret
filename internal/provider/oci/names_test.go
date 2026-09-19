package oci

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathToken(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"empty", "", ""},
		{"root", "/", ""},
		{"single", "/myapp", "myapp"},
		{"nested", "/myapp/prod", "myapp-prod"},
		{"deep", "/myapp/prod/eu", "myapp-prod-eu"},
		{"trailing slash", "/myapp/prod/", "myapp-prod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pathToken(tt.path))
		})
	}
}

func TestSecretNameFor(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		key     string
		want    string
		wantErr bool
	}{
		{"full key", "/myapp/prod", "/myapp/prod/DATABASE_URL", "myapp-prod_DATABASE_URL", false},
		{"bare leaf via library", "/myapp/prod", "DATABASE_URL", "myapp-prod_DATABASE_URL", false},
		{"root path absolute key", "", "/DATABASE_URL", "DATABASE_URL", false},
		{"root path bare key", "", "DATABASE_URL", "DATABASE_URL", false},
		{"root slash path", "/", "/DATABASE_URL", "DATABASE_URL", false},
		{"leaf with slash encoded", "/myapp/prod", "/myapp/prod/api/key", "myapp-prod_api-key", false},
		{"empty key", "/myapp/prod", "", "", true},
		{"key equals path", "/myapp/prod", "/myapp/prod", "", true},
		{"outside path", "/myapp/prod", "/other/DATABASE_URL", "", true},
		{"invalid chars", "", "DATABASE URL", "", true},
		{"unicode key", "", "КЛЮЧ", "", true},
		{"too long", "", strings.Repeat("K", 256), "", true},
		{"max length ok", "", strings.Repeat("K", 255), strings.Repeat("K", 255), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := secretNameFor(tt.path, tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretKeyFor(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		secret string
		want   string
		wantOK bool
	}{
		{"member", "/myapp/prod", "myapp-prod_DATABASE_URL", "/myapp/prod/DATABASE_URL", true},
		{"root prefix takes all", "", "any_name_at_all", "any_name_at_all", true},
		{"root slash prefix takes all", "/", "any_name", "any_name", true},
		{"other path excluded", "/myapp/prod", "other_DB", "", false},
		{"sibling prefix not confused", "/myapp", "myapp2_DB", "", false},
		{"sibling own prefix matches", "/myapp2", "myapp2_DB", "/myapp2/DB", true},
		{"empty leaf excluded", "/myapp", "myapp_", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := secretKeyFor(tt.prefix, tt.secret)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretKeyForTrailingSlashPrefix(t *testing.T) {
	// A path configured with a trailing slash still reconstructs keys that
	// the env-name stripper recognizes (KeyToEnvName strips pathPrefix).
	got, ok := secretKeyFor("/myapp/prod/", "myapp-prod_DATABASE_URL")
	assert.True(t, ok)
	assert.Equal(t, "/myapp/prod/DATABASE_URL", got)
}

func TestSecretNameRoundTrip(t *testing.T) {
	tests := []struct {
		path string
		key  string
		want string
	}{
		{"", "DATABASE_URL", "DATABASE_URL"},
		{"/", "DATABASE_URL", "DATABASE_URL"},
		{"/myapp", "/myapp/DATABASE_URL", "/myapp/DATABASE_URL"},
		{"/myapp/prod", "/myapp/prod/DATABASE_URL", "/myapp/prod/DATABASE_URL"},
		{"/myapp/prod", "/myapp/prod/api_key_2", "/myapp/prod/api_key_2"},
		// A leading slash at root path is normalized away (OCI names are
		// flat and the provider stores root-path keys bare).
		{"", "/DATABASE_URL", "DATABASE_URL"},
		{"/", "/DATABASE_URL", "DATABASE_URL"},
	}
	for _, tt := range tests {
		name, err := secretNameFor(tt.path, tt.key)
		assert.NoError(t, err, "path=%q key=%q", tt.path, tt.key)
		got, ok := secretKeyFor(tt.path, name)
		assert.True(t, ok, "path=%q key=%q", tt.path, tt.key)
		assert.Equal(t, tt.want, got, "path=%q key=%q", tt.path, tt.key)
	}
}

func TestValidSecretName(t *testing.T) {
	assert.False(t, validSecretName(""))
	assert.True(t, validSecretName("a"))
	assert.True(t, validSecretName(strings.Repeat("a", 255)))
	assert.False(t, validSecretName(strings.Repeat("a", 256)))
	assert.True(t, validSecretName("App-Name_2.config"))
	assert.False(t, validSecretName("has space"))
	assert.False(t, validSecretName("has/slash"))
	assert.False(t, validSecretName("ключ"))
}
