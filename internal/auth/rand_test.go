package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyringAvailable_RandomError(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()

	// Fail on first call (probe)
	cryptoRandReader = &errorReader{err: errors.New("probe error")}
	assert.False(t, keyringAvailable(), "keyringAvailable should be false when probe generation fails")

	// Fail on second call (token)
	cryptoRandReader = &errorReader{err: errors.New("token error"), limit: 16}
	assert.False(t, keyringAvailable(), "keyringAvailable should be false when token generation fails")
}
