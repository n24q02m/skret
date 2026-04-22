package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/n24q02m/skret/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestWithAutoAuth_PassthroughOnSuccess(t *testing.T) {
	err := auth.WithAutoAuth(context.Background(), "doppler", func() error { return nil })
	assert.NoError(t, err)
}

func TestWithAutoAuth_PassthroughNonAuthError(t *testing.T) {
	want := errors.New("other failure")
	err := auth.WithAutoAuth(context.Background(), "doppler", func() error { return want })
	assert.ErrorIs(t, err, want)
}

func TestWithAutoAuth_NonInteractiveReturnsInstructive(t *testing.T) {
	t.Setenv("SKRET_NON_INTERACTIVE", "1")
	err := auth.WithAutoAuth(context.Background(), "doppler", func() error {
		return auth.ErrCredentialNotFound
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "skret auth doppler")
}

func TestIsAuthError_Various(t *testing.T) {
	tests := []struct {
		err    error
		isAuth bool
	}{
		{nil, false},
		{errors.New("something else"), false},
		{errors.New("got 401 unauthorized"), true},
		{errors.New("API returned 403"), true},
		{errors.New("UnauthorizedException: bad creds"), true},
		{errors.New("could not resolve credentials"), true},
		{auth.ErrCredentialNotFound, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.isAuth, auth.IsAuthError(tt.err), "error: %v", tt.err)
	}
}
