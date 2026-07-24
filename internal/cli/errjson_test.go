package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/cli"
	"github.com/n24q02m/skret/pkg/skret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderError_JSONEnvelope(t *testing.T) {
	var buf bytes.Buffer
	err := skret.NewError(skret.ExitNotFoundError, `secret "api-key" not found in /app/prod`, nil)
	cli.RenderError(&buf, err, "json")

	var got struct {
		Error       string `json:"error"`
		Code        int    `json:"code"`
		Remediation string `json:"remediation"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, `secret "api-key" not found in /app/prod`, got.Error)
	assert.Equal(t, skret.ExitNotFoundError, got.Code)
	assert.Empty(t, got.Remediation)
}

func TestRenderError_JSONEnvelopeCarriesRemediation(t *testing.T) {
	var buf bytes.Buffer
	base := skret.NewError(skret.ExitAuthError, "not authenticated", nil)
	err := skret.WithRemediation(base, "run: skret auth login aws --method=profile")
	cli.RenderError(&buf, err, "json")

	var got struct {
		Code        int    `json:"code"`
		Remediation string `json:"remediation"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, skret.ExitAuthError, got.Code)
	assert.Equal(t, "run: skret auth login aws --method=profile", got.Remediation)
}

func TestRenderError_TableFormatUnchanged(t *testing.T) {
	var buf bytes.Buffer
	err := errors.New("plain failure")
	cli.RenderError(&buf, err, "table")
	assert.Equal(t, "plain failure\n", buf.String(), "table format must stay byte-identical to the old fmt.Fprintln")
}

func TestRenderError_EmptyFormatDefaultsToTable(t *testing.T) {
	var buf bytes.Buffer
	err := errors.New("plain failure")
	cli.RenderError(&buf, err, "")
	assert.Equal(t, "plain failure\n", buf.String())
}

func TestRenderError_NilErrorNoOutput(t *testing.T) {
	var buf bytes.Buffer
	cli.RenderError(&buf, nil, "json")
	assert.Empty(t, buf.String())
}
