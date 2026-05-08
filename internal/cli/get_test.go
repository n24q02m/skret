package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintSecret(t *testing.T) {
	secret := &provider.Secret{
		Key:     "TEST_KEY",
		Value:   "test-value",
		Version: 1,
		Meta: provider.SecretMeta{
			Description: "test description",
		},
	}

	tests := []struct {
		name         string
		outputJSON   bool
		withMetadata bool
		plain        bool
		want         string
	}{
		{
			name: "default output",
			want: "test-value\n",
		},
		{
			name:  "plain output",
			plain: true,
			want:  "test-value",
		},
		{
			name:       "json output",
			outputJSON: true,
			want:       "{\n  \"key\": \"TEST_KEY\",\n  \"value\": \"test-value\"\n}\n",
		},
		{
			name:         "with metadata output",
			withMetadata: true,
			want:         "{\n  \"key\": \"TEST_KEY\",\n  \"meta\": {\n    \"Description\": \"test description\",\n    \"Tags\": null,\n    \"CreatedAt\": \"0001-01-01T00:00:00Z\",\n    \"UpdatedAt\": \"0001-01-01T00:00:00Z\",\n    \"CreatedBy\": \"\"\n  },\n  \"value\": \"test-value\",\n  \"version\": 1\n}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			cmd := newGetCmd(&GlobalOpts{})
			cmd.SetOut(buf)

			err := printSecret(cmd, secret, tt.outputJSON, tt.withMetadata, tt.plain)
			require.NoError(t, err)

			if tt.outputJSON || tt.withMetadata {
				// For JSON, we might want to unmarshal and check fields to be more robust,
				// but since we are testing the formatting logic, string comparison is fine.
				// However, if the order of keys changes, string comparison might fail.
				// Let's unmarshal if it's JSON.
				var gotMap, wantMap map[string]any
				err := json.Unmarshal(buf.Bytes(), &gotMap)
				require.NoError(t, err)
				err = json.Unmarshal([]byte(tt.want), &wantMap)
				require.NoError(t, err)
				assert.Equal(t, wantMap, gotMap)
			} else {
				assert.Equal(t, tt.want, buf.String())
			}
		})
	}
}
