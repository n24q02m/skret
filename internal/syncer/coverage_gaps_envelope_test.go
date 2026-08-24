package syncer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func coverageEnvelopeClone(envelope *ExecutorEnvelope) *ExecutorEnvelope {
	clone := *envelope
	clone.Body = append([]byte(nil), envelope.Body...)
	clone.Signature = append([]byte(nil), envelope.Signature...)
	return &clone
}

func TestEnvelope_CanonicalWrappersAndValidationBoundaries(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	envelope := mustReplayEnvelope(t, privateKey, "operator", "hub", "nonce-validation", now.Add(time.Minute), []byte("payload"))

	canonical, err := envelope.CanonicalSigningBytes()
	require.NoError(t, err)
	alias, err := envelope.CanonicalBytes()
	require.NoError(t, err)
	wrapper, err := CanonicalSigningBytes(envelope)
	require.NoError(t, err)
	assert.Equal(t, canonical, alias)
	assert.Equal(t, canonical, wrapper)

	var missing *ExecutorEnvelope
	_, err = missing.CanonicalSigningBytes()
	require.ErrorContains(t, err, "missing envelope")
	_, err = missing.CanonicalBytes()
	require.ErrorContains(t, err, "missing envelope")
	_, err = CanonicalSigningBytes(nil)
	require.ErrorContains(t, err, "missing envelope")

	tests := []struct {
		name   string
		mutate func(*ExecutorEnvelope)
	}{
		{name: "unsupported version", mutate: func(value *ExecutorEnvelope) { value.Version++ }},
		{name: "missing audience", mutate: func(value *ExecutorEnvelope) { value.Audience = " " }},
		{name: "missing role", mutate: func(value *ExecutorEnvelope) { value.Role = "\t" }},
		{name: "missing manifest digest", mutate: func(value *ExecutorEnvelope) { value.ManifestDigest = "" }},
		{name: "invalid manifest digest", mutate: func(value *ExecutorEnvelope) { value.ManifestDigest = "sha256:" + strings.Repeat("A", 64) }},
		{name: "missing body digest", mutate: func(value *ExecutorEnvelope) { value.BodyDigest = "" }},
		{name: "invalid body digest", mutate: func(value *ExecutorEnvelope) { value.BodyDigest = "sha256:" + strings.Repeat("A", 64) }},
		{name: "missing nonce", mutate: func(value *ExecutorEnvelope) { value.Nonce = "" }},
		{name: "missing body", mutate: func(value *ExecutorEnvelope) { value.Body = nil }},
		{name: "body digest mismatch", mutate: func(value *ExecutorEnvelope) { value.BodyDigest = digestBytes([]byte("different")) }},
		{name: "zero expiry", mutate: func(value *ExecutorEnvelope) { value.ExpiresAt = time.Time{} }},
		{name: "invalid expiry encoding", mutate: func(value *ExecutorEnvelope) { value.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{name: "invalid signature length", mutate: func(value *ExecutorEnvelope) { value.Signature = []byte("short") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := coverageEnvelopeClone(envelope)
			test.mutate(mutated)
			err := VerifySignedEnvelope(mutated, publicKey, now)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "payload")
		})
	}

	invalidVerifier := coverageEnvelopeClone(envelope)
	require.ErrorContains(t, VerifySignedEnvelope(invalidVerifier, ed25519.PublicKey("short"), now), "invalid verifier key")
	require.ErrorContains(t, VerifySignedEnvelope(nil, publicKey, now), "missing envelope")
}

func TestEnvelope_BuildCopiesBodyAndClientConstructorDefaults(t *testing.T) {
	now := replayTestTime()
	publicKey, privateKey := replayTestKeys(t)
	body := []byte("mutable-body")
	envelope, err := BuildSignedEnvelope("sha256:"+strings.Repeat("a", 64), "operator", "hub", "nonce-copy", now.Add(time.Minute), body, privateKey, now)
	require.NoError(t, err)
	body[0] = 'X'
	assert.Equal(t, []byte("mutable-body"), envelope.Body)
	require.NoError(t, VerifySignedEnvelope(envelope, publicKey, now))

	client := NewEnvelopeClient("http://example.test", privateKey)
	require.NotNil(t, client)
	assert.Equal(t, "http://example.test", client.BaseURL)
	assert.Equal(t, privateKey, client.Signer)
	assert.Nil(t, client.HTTPClient)
	assert.Nil(t, client.Clock)
}

func TestEnvelope_FixedURLRejectsNonOriginsAndAcceptsRoot(t *testing.T) {
	invalid := []string{
		"://",
		"ftp://example.test",
		"https:///missing-host",
		"https://user:password@example.test",
		"https://example.test/path",
		"https://example.test/%2f",
		"https://example.test/?query=value",
		"https://example.test#fragment",
		"http:opaque-value",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			_, err := fixedEnvelopeURL(raw)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "password")
		})
	}

	endpoint, err := fixedEnvelopeURL("HTTPS://Example.test/")
	require.NoError(t, err)
	assert.Equal(t, "/operator/executor-envelope", strings.TrimPrefix(endpoint, "https://Example.test"))
	assert.Contains(t, endpoint, "operator/executor-envelope")
}

func TestEnvelopeClientSubmit_FailsClosedAtClientAndTransportBoundaries(t *testing.T) {
	now := replayTestTime()
	_, privateKey := replayTestKeys(t)
	validDigest := "sha256:" + strings.Repeat("a", 64)
	validBody := []byte("payload")

	var nilClient *EnvelopeClient
	_, err := nilClient.Submit(t.Context(), validDigest, "operator", "hub", "nonce", now.Add(time.Minute), validBody)
	require.ErrorContains(t, err, "missing client")

	base := func() *EnvelopeClient {
		return &EnvelopeClient{
			BaseURL:               "http://example.test",
			Signer:                privateKey,
			OperatorSessionCookie: "session=synthetic",
			Clock:                 func() time.Time { return now },
		}
	}

	t.Run("transport error is value free", func(t *testing.T) {
		client := base()
		client.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("transport leaked payload")
		})}
		_, err := client.Submit(t.Context(), validDigest, "operator", "hub", "nonce", now.Add(time.Minute), validBody)
		require.ErrorContains(t, err, "submit request failed")
		assert.NotContains(t, err.Error(), "payload")
	})

	t.Run("nil context rejects request creation", func(t *testing.T) {
		client := base()
		var nilContext context.Context
		_, err := client.Submit(nilContext, validDigest, "operator", "hub", "nonce", now.Add(time.Minute), validBody)
		require.ErrorContains(t, err, "request creation failed")
	})

	t.Run("response read error is hidden", func(t *testing.T) {
		client := base()
		client.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       coverageErrorReadCloser{},
				Header:     make(http.Header),
			}, nil
		})}
		_, err := client.Submit(t.Context(), validDigest, "operator", "hub", "nonce", now.Add(time.Minute), validBody)
		require.ErrorContains(t, err, "response read failed")
		assert.NotContains(t, err.Error(), "payload")
	})

	t.Run("default HTTP client succeeds through httptest", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "session=synthetic", r.Header.Get("Cookie"))
			_, _ = w.Write([]byte("accepted"))
		}))
		defer server.Close()
		client := NewEnvelopeClient(server.URL, privateKey)
		client.OperatorSessionCookie = "session=synthetic"
		client.Clock = func() time.Time { return now }
		response, err := client.Submit(t.Context(), validDigest, "operator", "hub", "nonce", now.Add(time.Minute), validBody)
		require.NoError(t, err)
		assert.Equal(t, []byte("accepted"), response)
	})
}

type coverageErrorReadCloser struct{}

func (coverageErrorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("response body contains payload")
}

func (coverageErrorReadCloser) Close() error { return nil }

var _ io.ReadCloser = coverageErrorReadCloser{}

func TestPerKeyAdaptersRejectNilSecretsAndCanceledRequests(t *testing.T) {
	var nilWorker *cloudflareWorkerSyncer
	require.Error(t, nilWorker.SyncKey(context.Background(), &provider.Secret{Key: "K", Value: "v"}))
	require.Error(t, (&cloudflareWorkerSyncer{}).SyncKey(context.Background(), &provider.Secret{Key: "K", Value: "v"}))
	worker := &cloudflareWorkerSyncer{CloudflareSyncer: NewCloudflare("account", "worker", "", "token", "://invalid").(*CloudflareSyncer)}
	require.Error(t, worker.SyncKey(context.Background(), nil))

	github := NewGitHub("owner", "repo", "token", "https://api.github.com").(*GitHubSyncer)
	require.Error(t, github.SyncKey(context.Background(), nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, github.Sync(ctx, []*provider.Secret{{Key: "K", Value: "v"}}))
}
