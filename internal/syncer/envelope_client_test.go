package syncer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSignedEnvelope_VerifiesCanonicalAuthorityAndBodyBinding(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	body := []byte(`{"operation":"sync"}`)
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	expiresAt := now.Add(5 * time.Minute)

	envelope, err := BuildSignedEnvelope(manifestDigest, "operator", "hub", "nonce-123", expiresAt, body, privateKey, now)
	require.NoError(t, err)
	require.NotNil(t, envelope)
	assert.Equal(t, EnvelopeVersion, envelope.Version)
	assert.Equal(t, "nonce-123", envelope.Nonce)
	assert.Equal(t, body, envelope.Body)
	digest := sha256.Sum256(body)
	assert.Equal(t, "sha256:"+hex.EncodeToString(digest[:]), envelope.BodyDigest)
	require.NoError(t, VerifySignedEnvelope(envelope, publicKey, now))

	first, err := envelope.CanonicalSigningBytes()
	require.NoError(t, err)
	second, err := envelope.CanonicalSigningBytes()
	require.NoError(t, err)
	assert.Equal(t, first, second)

	originalSignature := append([]byte(nil), envelope.Signature...)
	envelope.Signature[0] ^= 0xff
	third, err := envelope.CanonicalSigningBytes()
	require.NoError(t, err)
	assert.Equal(t, first, third, "detached signature must not be signed")
	envelope.Signature = originalSignature

	envelope.Role = "other-role"
	assert.Error(t, VerifySignedEnvelope(envelope, publicKey, now))
}

func TestVerifySignedEnvelope_RejectsBodyAndDigestTampering(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	envelope, err := BuildSignedEnvelope(
		"sha256:"+strings.Repeat("a", 64),
		"operator",
		"hub",
		"nonce-123",
		now.Add(time.Minute),
		[]byte("payload"),
		privateKey,
		now,
	)
	require.NoError(t, err)

	envelope.Body[0] ^= 1
	assert.Error(t, VerifySignedEnvelope(envelope, publicKey, now))

	envelope.Body[0] ^= 1
	envelope.BodyDigest = "sha256:" + strings.Repeat("c", 64)
	assert.Error(t, VerifySignedEnvelope(envelope, publicKey, now))
}

func TestBuildSignedEnvelope_RejectsInvalidFieldsAndLifetime(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	validDigest := "sha256:" + strings.Repeat("a", 64)
	validBody := []byte("payload")

	tests := []struct {
		name       string
		manifest   string
		role       string
		audience   string
		nonce      string
		expiresAt  time.Time
		body       []byte
		signer     ed25519.PrivateKey
	}{
		{name: "missing manifest digest", manifest: "", role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), body: validBody, signer: privateKey},
		{name: "invalid manifest digest", manifest: "not-a-digest", role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), body: validBody, signer: privateKey},
		{name: "missing role", manifest: validDigest, role: "", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), body: validBody, signer: privateKey},
		{name: "missing audience", manifest: validDigest, role: "operator", audience: "", nonce: "nonce", expiresAt: now.Add(time.Minute), body: validBody, signer: privateKey},
		{name: "missing nonce", manifest: validDigest, role: "operator", audience: "hub", nonce: "", expiresAt: now.Add(time.Minute), body: validBody, signer: privateKey},
		{name: "empty body", manifest: validDigest, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), body: nil, signer: privateKey},
		{name: "zero expiry", manifest: validDigest, role: "operator", audience: "hub", nonce: "nonce", expiresAt: time.Time{}, body: validBody, signer: privateKey},
		{name: "expired", manifest: validDigest, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now, body: validBody, signer: privateKey},
		{name: "overlong ttl", manifest: validDigest, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(MaxEnvelopeTTL + time.Nanosecond), body: validBody, signer: privateKey},
		{name: "invalid signer", manifest: validDigest, role: "operator", audience: "hub", nonce: "nonce", expiresAt: now.Add(time.Minute), body: validBody, signer: ed25519.PrivateKey("short")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSignedEnvelope(tc.manifest, tc.role, tc.audience, tc.nonce, tc.expiresAt, tc.body, tc.signer, now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "payload")
			assert.NotContains(t, err.Error(), "not-a-digest")
		})
	}
}

func TestVerifySignedEnvelope_UsesInjectedClockAndLeavesNonceReplayToExecutor(t *testing.T) {
	createdAt := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	body := []byte("payload")
	envelope, err := BuildSignedEnvelope(
		"sha256:"+strings.Repeat("a", 64),
		"operator",
		"hub",
		"replayable-nonce",
		createdAt.Add(time.Minute),
		body,
		privateKey,
		createdAt,
	)
	require.NoError(t, err)

	require.NoError(t, VerifySignedEnvelope(envelope, publicKey, createdAt.Add(30*time.Second)))
	assert.Equal(t, "replayable-nonce", envelope.Nonce)
	assert.NoError(t, VerifySignedEnvelope(envelope, publicKey, createdAt.Add(30*time.Second)), "signature verification does not accept or track nonce replay")
	assert.Error(t, VerifySignedEnvelope(envelope, publicKey, createdAt.Add(2*time.Minute)))
}

func TestEnvelopeClientSubmit_UsesFixedHubPathAndVerifiesEnvelope(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	body := []byte(`{"operation":"sync"}`)
	var seenPath string
	var seenMethod string
	var seenContentType string
	var seenEnvelope SignedEnvelope
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenMethod = r.Method
		seenContentType = r.Header.Get("Content-Type")
		data, readErr := io.ReadAll(r.Body)
		require.NoError(t, readErr)
		require.NoError(t, json.Unmarshal(data, &seenEnvelope))
		require.NoError(t, VerifySignedEnvelope(&seenEnvelope, publicKey, now))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer server.Close()

	client := &EnvelopeClient{
		BaseURL:    server.URL,
		Signer:     privateKey,
		HTTPClient: server.Client(),
		Clock:      func() time.Time { return now },
	}
	response, err := client.Submit(t.Context(), manifestDigest, "operator", "hub", "nonce-submit", now.Add(time.Minute), body)
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"accepted":true}`), response)
	assert.Equal(t, "/operator/executor-envelope", seenPath)
	assert.Equal(t, http.MethodPost, seenMethod)
	assert.Equal(t, "application/json", seenContentType)
	assert.Equal(t, "nonce-submit", seenEnvelope.Nonce)
}

func TestEnvelopeClientSubmit_RejectsRedirectingBaseURLs(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	validDigest := "sha256:" + strings.Repeat("a", 64)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	for _, rawBaseURL := range []string{
		"https://example.test/operator",
		"https://example.test/operator/",
		"https://example.test/?next=/executor",
		"https://example.test/#executor",
		"https://user:password@example.test",
	} {
		t.Run(rawBaseURL, func(t *testing.T) {
			client := &EnvelopeClient{BaseURL: rawBaseURL, Signer: privateKey, Clock: func() time.Time { return now }}
			_, err := client.Submit(t.Context(), validDigest, "operator", "hub", "nonce", now.Add(time.Minute), []byte("payload"))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "password")
			assert.NotContains(t, err.Error(), "payload")
		})
	}

	parsed, err := url.Parse("https://example.test/")
	require.NoError(t, err)
	assert.Nil(t, parsed.User)
}

func TestEnvelopeClientSubmit_BoundsSuccessfulResponseAndHidesErrorBody(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	requestBody := []byte("payload")

	t.Run("oversized success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte("x"), MaxEnvelopeResponseBytes+1))
		}))
		defer server.Close()
		client := &EnvelopeClient{BaseURL: server.URL, Signer: privateKey, HTTPClient: server.Client(), Clock: func() time.Time { return now }}
		_, err := client.Submit(t.Context(), manifestDigest, "operator", "hub", "nonce", now.Add(time.Minute), requestBody)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "response")
		assert.NotContains(t, err.Error(), "xxx")
	})

	t.Run("non-2xx status only", func(t *testing.T) {
		const responseBody = "private-response-body"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(responseBody))
		}))
		defer server.Close()
		client := &EnvelopeClient{BaseURL: server.URL, Signer: privateKey, HTTPClient: server.Client(), Clock: func() time.Time { return now }}
		_, err := client.Submit(t.Context(), manifestDigest, "operator", "hub", "nonce", now.Add(time.Minute), requestBody)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "502")
		assert.NotContains(t, err.Error(), responseBody)
		assert.NotContains(t, err.Error(), "payload")
	})
}

func TestEnvelopeClientSubmit_DoesNotFollowRedirectsToAnotherPath(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/direct-executor")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := &EnvelopeClient{BaseURL: server.URL, Signer: privateKey, HTTPClient: server.Client(), Clock: func() time.Time { return now }}
	_, err = client.Submit(t.Context(), "sha256:"+strings.Repeat("a", 64), "operator", "hub", "nonce", now.Add(time.Minute), []byte("payload"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "307")
	assert.False(t, redirected)
}
