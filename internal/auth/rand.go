package auth

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// cryptoRandReader is a package-level variable for the random source,
// allowing it to be mocked in tests.
var cryptoRandReader = rand.Reader

// randomString returns a base64url-encoded random string of n bytes.
func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(cryptoRandReader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
