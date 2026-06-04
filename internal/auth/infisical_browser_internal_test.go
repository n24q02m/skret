package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPkcePair_Error(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()
	cryptoRandReader = &errorReader{err: errors.New("random error")}

	v, c, err := pkcePair()
	assert.Error(t, err)
	assert.Empty(t, v)
	assert.Empty(t, c)
}

func TestInfisicalBrowserFlow_Login_StateError(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()
	cryptoRandReader = &errorReader{err: errors.New("state error")}

	flow := NewInfisicalBrowserFlow("")
	_, err := flow.Login(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: state")
}

func TestInfisicalBrowserFlow_Login_PkceError(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()
	// Succeed for state (32 bytes), then fail for pkce (32 bytes)
	cryptoRandReader = &errorReader{err: errors.New("pkce error"), limit: 32}

	flow := NewInfisicalBrowserFlow("")
	_, err := flow.Login(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "infisical browser: pkce")
}
