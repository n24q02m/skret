// Package notify posts names-only webhook notifications after successful
// secret mutations (set/delete/rotate/sync). Payloads carry key names and
// event metadata only -- secret values are never included. Delivery is
// bounded (5s per attempt), retries once on 5xx, and can sign each request
// body with HMAC-SHA256 (X-Skret-Signature) for receivers that verify it.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/n24q02m/skret/internal/config"
)

// Event is a secret mutation kind reported to webhooks.
type Event string

const (
	EventSet    Event = config.NotifyEventSet
	EventDelete Event = config.NotifyEventDelete
	EventRotate Event = config.NotifyEventRotate
	EventSync   Event = config.NotifyEventSync
)

// ValidEvent reports whether name is a known mutation event. It delegates to
// the config vocabulary so .skret.yaml notify.events validation and webhook
// payloads can never drift apart.
func ValidEvent(name string) bool { return config.ValidNotifyEvent(name) }

const (
	// Timeout bounds each webhook POST attempt. Delivery is fire-and-report
	// from the caller's perspective; a hung receiver must never hang a
	// mutation command.
	Timeout = 5 * time.Second
	// SignatureHeader carries the HMAC-SHA256 body signature as
	// "sha256=<hex>" when notify.secret is configured. Receivers compute
	// HMAC-SHA256(notify.secret, raw request body) and compare.
	SignatureHeader = "X-Skret-Signature"
)

// ActorEnvVar, when set in the environment, is reported as the payload's
// actor (e.g. SKRET_ACTOR=ci in a pipeline). Empty means the field is
// omitted -- skret never guesses an identity.
const ActorEnvVar = "SKRET_ACTOR"

// Payload is the webhook request body. Names only -- never secret values.
type Payload struct {
	Event     string   `json:"event"`
	KeyNames  []string `json:"key_names"`
	Env       string   `json:"env"`
	Timestamp string   `json:"timestamp"` // RFC3339, UTC
	Actor     string   `json:"actor,omitempty"`
}

// Notifier posts mutation payloads to configured webhook URLs. The zero
// useful value is nil: a nil *Notifier is disabled and every method is a
// no-op, which is what commands get when .skret.yaml has no notify block.
type Notifier struct {
	URLs   []string
	Events map[string]bool // nil = every event fires
	Secret string          // HMAC-SHA256 key; empty = no signature header
	Client *http.Client    // nil = default client with Timeout
	// Now overrides the clock (tests); nil means time.Now.
	Now func() time.Time
}

// FromConfig builds a Notifier from the .skret.yaml notify block. A nil
// config or one with no URLs returns nil (the disabled, zero-cost case).
func FromConfig(cfg *config.NotifyConfig) *Notifier {
	if cfg == nil || len(cfg.WebhookURLs) == 0 {
		return nil
	}
	var allowed map[string]bool
	if len(cfg.Events) > 0 {
		allowed = make(map[string]bool, len(cfg.Events))
		for _, e := range cfg.Events {
			allowed[e] = true
		}
	}
	return &Notifier{
		URLs:   append([]string(nil), cfg.WebhookURLs...),
		Events: allowed,
		Secret: cfg.Secret,
	}
}

// Enabled reports whether ev passes the configured notify.events filter.
// A nil notifier is never enabled.
func (n *Notifier) Enabled(ev Event) bool {
	if n == nil {
		return false
	}
	return n.Events == nil || n.Events[string(ev)]
}

// Send posts one mutation event to every configured webhook URL. The same
// body (hence the same signature) goes to each URL; every URL must accept
// the delivery for Send to succeed. A 5xx response is retried once per URL;
// transport errors and other non-2xx statuses fail that URL immediately.
// Send is a no-op for a nil notifier, a filtered event, or an empty key
// list -- nothing mutated, nothing to report.
func (n *Notifier) Send(ctx context.Context, ev Event, env string, keyNames []string) error {
	if n == nil || !n.Enabled(ev) || len(keyNames) == 0 {
		return nil
	}
	now := n.Now
	if now == nil {
		now = time.Now
	}
	body, err := json.Marshal(Payload{
		Event:     string(ev),
		KeyNames:  append([]string(nil), keyNames...),
		Env:       env,
		Timestamp: now().UTC().Format(time.RFC3339),
		Actor:     os.Getenv(ActorEnvVar),
	})
	if err != nil {
		return fmt.Errorf("notify: encode payload: %w", err)
	}

	var failures []string
	for _, rawURL := range n.URLs {
		if err := n.deliver(ctx, rawURL, body); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", rawURL, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("notify: webhook delivery failed (%s)", strings.Join(failures, "; "))
	}
	return nil
}

// deliver POSTs the pre-encoded body to one URL with one 5xx retry.
func (n *Notifier) deliver(ctx context.Context, rawURL string, body []byte) error {
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}

	var lastErr error
	for range 2 {
		// A fresh request per attempt: the body reader is consumed and the
		// signature is deterministic over the same bytes either way.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if n.Secret != "" {
			mac := hmac.New(sha256.New, []byte(n.Secret))
			mac.Write(body)
			req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post: %w", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			return lastErr // a 4xx will not get better on retry
		}
	}
	return lastErr
}
