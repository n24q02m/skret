package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/internal/notify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureServer records every request's body and headers.
type captureServer struct {
	*httptest.Server
	bodies  chan []byte
	headers chan http.Header
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	c := &captureServer{
		bodies:  make(chan []byte, 8),
		headers: make(chan http.Header, 8),
	}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		c.bodies <- body
		c.headers <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.Server.Close)
	return c
}

func TestNotify_Send_PayloadShape_NamesOnly(t *testing.T) {
	srv := newCaptureServer(t)
	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	require.NotNil(t, n)

	// The value that must never travel: the caller passes names only, and
	// the payload encoder must not smuggle anything else in.
	err := n.Send(context.Background(), notify.EventSet, "prod", []string{"/myapp/prod/API_KEY"})
	require.NoError(t, err)

	var payload notify.Payload
	require.NoError(t, json.Unmarshal(<-srv.bodies, &payload))
	assert.Equal(t, "set", payload.Event)
	assert.Equal(t, []string{"/myapp/prod/API_KEY"}, payload.KeyNames)
	assert.Equal(t, "prod", payload.Env)
	assert.Empty(t, payload.Actor, "actor must be omitted when SKRET_ACTOR is unset")

	_, err = time.Parse(time.RFC3339, payload.Timestamp)
	assert.NoError(t, err, "timestamp must be RFC3339")

	headers := <-srv.headers
	assert.Equal(t, "application/json", headers.Get("Content-Type"))
	assert.Empty(t, headers.Get(notify.SignatureHeader), "no signature without notify.secret")
}

func TestNotify_Send_HMACSignature(t *testing.T) {
	srv := newCaptureServer(t)
	n := notify.FromConfig(&config.NotifyConfig{
		WebhookURLs: config.WebhookURLs{srv.URL},
		Secret:      "hunter2",
	})
	require.NotNil(t, n)

	require.NoError(t, n.Send(context.Background(), notify.EventDelete, "prod", []string{"OLD_TOKEN"}))

	body := <-srv.bodies
	headers := <-srv.headers

	mac := hmac.New(sha256.New, []byte("hunter2"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.Equal(t, want, headers.Get(notify.SignatureHeader),
		"signature must be HMAC-SHA256 over the exact raw body")
}

func TestNotify_Send_MultipleURLs_SameBody(t *testing.T) {
	a := newCaptureServer(t)
	b := newCaptureServer(t)
	n := notify.FromConfig(&config.NotifyConfig{
		WebhookURLs: config.WebhookURLs{a.URL, b.URL},
	})
	require.NotNil(t, n)

	require.NoError(t, n.Send(context.Background(), notify.EventSync, "dev", []string{"K1", "K2"}))

	bodyA := <-a.bodies
	bodyB := <-b.bodies
	assert.JSONEq(t, string(bodyA), string(bodyB), "every URL receives the same payload")
	var payload notify.Payload
	require.NoError(t, json.Unmarshal(bodyA, &payload))
	assert.Equal(t, "sync", payload.Event)
	assert.Equal(t, []string{"K1", "K2"}, payload.KeyNames)
}

func TestNotify_Send_RetriesOnceOn5xx(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	require.NoError(t, n.Send(context.Background(), notify.EventSet, "dev", []string{"K"}))
	assert.Equal(t, int32(2), requests.Load(), "exactly one retry after a 5xx")
}

func TestNotify_Send_5xxTwice_Fails(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	err := n.Send(context.Background(), notify.EventSet, "dev", []string{"K"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")
	assert.Equal(t, int32(2), requests.Load(), "5xx is retried once, not forever")
}

func TestNotify_Send_4xx_NoRetry(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	err := n.Send(context.Background(), notify.EventSet, "dev", []string{"K"})
	require.Error(t, err)
	assert.Equal(t, int32(1), requests.Load(), "a 4xx must not be retried")
}

func TestNotify_Send_EventFilter(t *testing.T) {
	srv := newCaptureServer(t)
	n := notify.FromConfig(&config.NotifyConfig{
		WebhookURLs: config.WebhookURLs{srv.URL},
		Events:      []string{"set"},
	})
	require.NotNil(t, n)

	require.NoError(t, n.Send(context.Background(), notify.EventDelete, "dev", []string{"K"}))
	require.NoError(t, n.Send(context.Background(), notify.EventRotate, "dev", []string{"K"}))
	select {
	case body := <-srv.bodies:
		t.Fatalf("filtered-out event must not POST, got body %s", body)
	default:
	}

	require.NoError(t, n.Send(context.Background(), notify.EventSet, "dev", []string{"K"}))
	var payload notify.Payload
	require.NoError(t, json.Unmarshal(<-srv.bodies, &payload))
	assert.Equal(t, "set", payload.Event)
}

func TestNotify_Send_NilNotifier_Noop(t *testing.T) {
	var n *notify.Notifier
	assert.False(t, n.Enabled(notify.EventSet))
	require.NoError(t, n.Send(context.Background(), notify.EventSet, "dev", []string{"K"}),
		"a repo without a notify block must be a silent no-op")
	assert.Nil(t, notify.FromConfig(nil))
	assert.Nil(t, notify.FromConfig(&config.NotifyConfig{}))
}

func TestNotify_Send_EmptyKeyNames_Noop(t *testing.T) {
	srv := newCaptureServer(t)
	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	require.NotNil(t, n)

	require.NoError(t, n.Send(context.Background(), notify.EventSync, "dev", nil))
	select {
	case body := <-srv.bodies:
		t.Fatalf("empty key list must not POST, got body %s", body)
	default:
	}
}

func TestNotify_Send_ActorFromEnv(t *testing.T) {
	srv := newCaptureServer(t)
	t.Setenv(notify.ActorEnvVar, "ci-bot")
	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	require.NotNil(t, n)

	require.NoError(t, n.Send(context.Background(), notify.EventSet, "dev", []string{"K"}))
	var payload notify.Payload
	require.NoError(t, json.Unmarshal(<-srv.bodies, &payload))
	assert.Equal(t, "ci-bot", payload.Actor)
}

func TestNotify_Send_UnreachableURL_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	url := srv.URL
	srv.Close() // nothing listens anymore

	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{url}})
	err := n.Send(context.Background(), notify.EventSet, "dev", []string{"K"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "webhook delivery failed")
}

func TestNotify_Send_TimeoutBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	n := notify.FromConfig(&config.NotifyConfig{WebhookURLs: config.WebhookURLs{srv.URL}})
	n.Client = &http.Client{Timeout: 50 * time.Millisecond} // shrink for the test

	start := time.Now()
	err := n.Send(context.Background(), notify.EventSet, "dev", []string{"K"})
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second, "delivery must be timeout-bounded, not hang")
}

func TestNotify_ValidEvent(t *testing.T) {
	for _, name := range []string{"set", "delete", "rotate", "sync"} {
		assert.True(t, notify.ValidEvent(name), name)
	}
	for _, name := range []string{"", "SET", "update", "webhook"} {
		assert.False(t, notify.ValidEvent(name), name)
	}
}
