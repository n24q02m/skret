package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeKey(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "DATABASE_URL", want: "DATABASE-URL"},
		{name: "already clean", in: "DB-URL", want: "DB-URL"},
		{name: "path separators", in: "/myapp/prod/KEY", want: "myapp-prod-KEY"},
		{name: "dots and underscores", in: "app.config.v2_beta", want: "app-config-v2-beta"},
		{name: "unicode", in: "ключ", want: ""},
		{name: "collapse runs", in: "a///b___c", want: "a-b-c"},
		{name: "trims dashes", in: "--key--", want: "key"},
		{name: "caps at 127", in: repeat('x', 200), want: repeat('x', 127)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeKey(tt.in)
			if tt.want == "" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, len(got), maxNameLen)
		})
	}
}

// repeat builds an n-length string of r without importing strings twice.
func repeat(r byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = r
	}
	return string(out)
}

func TestVersionNumber(t *testing.T) {
	// A real-world-shaped 32-char hex ID folds deterministically into the
	// positive int64 space.
	id := "2f5c1a9b8d3e47f60a1b2c3d4e5f6071"
	n1 := versionNumber(id)
	assert.Equal(t, n1, versionNumber(id))
	assert.Greater(t, n1, int64(0))
	assert.Less(t, n1, int64(1)<<62)

	// Case-insensitive: Key Vault IDs are lowercase but never rely on that.
	assert.Equal(t, n1, versionNumber("2F5C1A9B8D3E47F60A1B2C3D4E5F6071"))

	// Distinct IDs fold to distinct numbers in practice.
	assert.NotEqual(t, n1, versionNumber("1f5c1a9b8d3e47f60a1b2c3d4e5f6071"))

	// Short or non-hex IDs take the FNV fallback path.
	fallback := versionNumber("short")
	assert.Greater(t, fallback, int64(0))
	assert.Equal(t, fallback, versionNumber("short"))
}
