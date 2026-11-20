package keystore

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSealToPublicKeyOpensWithPrivateKey pins the encrypt-only arm of
// recipientFor: material that is an age public key (age1...) seals an
// envelope that only the matching private key opens.
func TestSealToPublicKeyOpensWithPrivateKey(t *testing.T) {
	id, err := age.ParseX25519Identity(testIdentity)
	require.NoError(t, err)

	raw, err := Seal(map[string]string{"API_KEY": "value-1"}, id.Recipient().String())
	require.NoError(t, err)

	got, err := Open(raw, testIdentity)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"API_KEY": "value-1"}, got)

	_, err = Open(raw, testMaterial)
	require.Error(t, err)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
}

// TestEmptyPassphraseRefusedByRecipientAndIdentity pins that the passphrase
// arm never derives a key from an empty passphrase, in either direction,
// and reports it as a validation error.
func TestEmptyPassphraseRefusedByRecipientAndIdentity(t *testing.T) {
	_, err := recipientFor("")
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
	assert.Contains(t, err.Error(), "build encryption recipient")

	_, err = identityFor("")
	require.Error(t, err)
	assert.Equal(t, CodeValidationError, exitCodeOf(t, err))
	assert.Contains(t, err.Error(), "build decryption identity")
}

// TestOpenTamperedPayloadIsAuthError pins the streaming half of the
// tamper contract: a valid header followed by a corrupted payload chunk
// fails as an AuthError with the key hint, never as a partial read.
func TestOpenTamperedPayloadIsAuthError(t *testing.T) {
	raw := sealForTest(t, map[string]string{"API_KEY": "value-1"})
	tampered := bytes.Clone(raw)
	tampered[len(tampered)-1] ^= 0xff

	got, err := Open(tampered, testMaterial)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, CodeAuthError, exitCodeOf(t, err))
	assert.Contains(t, remediationOf(err), "SKRET_AGE_KEY")
}

// TestOpenNonYAMLPayloadIsConfigError pins that an envelope that decrypts
// cleanly but does not hold a YAML payload is a config error (exit 2), not
// an auth error: the key was right, the content is not a skret payload.
func TestOpenNonYAMLPayloadIsConfigError(t *testing.T) {
	rec, err := recipientFor(testMaterial)
	require.NoError(t, err)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	require.NoError(t, err)
	_, err = w.Write([]byte("secrets: [unterminated"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	_, err = Open(buf.Bytes(), testMaterial)
	require.Error(t, err)
	assert.Equal(t, CodeConfigError, exitCodeOf(t, err))
	assert.Contains(t, err.Error(), "parse age payload")
}

// TestPlaintextEntropyWarningsUnparsableFile pins that a plaintext file that
// is not valid YAML produces no entropy warnings instead of an error: the
// warning is advisory and must never block the command that reads the file.
func TestPlaintextEntropyWarningsUnparsableFile(t *testing.T) {
	assert.Nil(t, plaintextEntropyWarnings([]byte("secrets: [unterminated")))
}
