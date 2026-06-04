package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type errorReader struct {
	err   error
	count int
	limit int
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.limit > 0 && r.count < r.limit {
		toRead := len(p)
		if r.count+toRead > r.limit {
			toRead = r.limit - r.count
		}
		for i := 0; i < toRead; i++ {
			p[i] = byte(i)
		}
		r.count += toRead
		return toRead, nil
	}
	return 0, r.err
}

func TestRandomString_Error(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()
	cryptoRandReader = &errorReader{err: errors.New("random error")}

	s, err := randomString(32)
	assert.Error(t, err)
	assert.Empty(t, s)
}

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

func TestRandomString_PartialReadError(t *testing.T) {
	oldReader := cryptoRandReader
	defer func() { cryptoRandReader = oldReader }()
	// Provide 10 bytes, then fail
	cryptoRandReader = &errorReader{err: errors.New("unexpected eof"), limit: 10}

	s, err := randomString(32)
	assert.Error(t, err)
	assert.Empty(t, s)
}
