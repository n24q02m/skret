package azure

import (
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func respErr(code string, status int) error {
	return &azcore.ResponseError{ErrorCode: code, StatusCode: status}
}

func TestMapError(t *testing.T) {
	err := mapError("get", "K", respErr("SecretNotFound", 404))
	assert.ErrorIs(t, err, provider.ErrNotFound)

	err = mapError("get", "K", respErr("NotFound", 404))
	assert.ErrorIs(t, err, provider.ErrNotFound)

	err = mapError("get", "K", respErr("Forbidden", 403))
	require.Error(t, err)
	assert.NotErrorIs(t, err, provider.ErrNotFound)
	assert.Contains(t, err.Error(), `azure: get "K"`)

	err = mapError("list", "/p", errors.New("boom"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestIsNotFound(t *testing.T) {
	assert.False(t, isNotFound(nil))
	assert.True(t, isNotFound(respErr("SecretNotFound", 404)))
	assert.True(t, isNotFound(respErr("NotFound", 404)))
	assert.True(t, isNotFound(respErr("", 404)), "bare 404 counts as not found")
	assert.False(t, isNotFound(respErr("Forbidden", 403)))
	assert.False(t, isNotFound(errors.New("transport")))
}

func TestSetErrorMayHaveCommitted(t *testing.T) {
	assert.False(t, setErrorMayHaveCommitted(respErr("BadRequest", 400)))
	assert.False(t, setErrorMayHaveCommitted(respErr("Unauthorized", 401)))
	assert.False(t, setErrorMayHaveCommitted(respErr("Forbidden", 403)))
	assert.False(t, setErrorMayHaveCommitted(respErr("Conflict", 409)))
	assert.True(t, setErrorMayHaveCommitted(respErr("InternalServerError", 500)))
	assert.True(t, setErrorMayHaveCommitted(respErr("BadGateway", 502)))
	assert.True(t, setErrorMayHaveCommitted(errors.New("connection reset")), "transport failures are ambiguous")
}
