package syncer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// EnvelopeVersion identifies the canonical signed envelope schema.
	EnvelopeVersion = 1

	// MaxEnvelopeTTL limits how far an envelope may expire after the injected
	// signing clock. Replay acceptance remains an executor/Hub responsibility.
	MaxEnvelopeTTL = 15 * time.Minute

	// MaxEnvelopeResponseBytes bounds the response returned by the future Hub
	// route. The client never includes a response body in an error.
	MaxEnvelopeResponseBytes = 1 << 20

	executorEnvelopePath = "/operator/executor-envelope"
)

// ExecutorEnvelope is the versioned, detached-signature request sent to the
// future Hub executor-envelope route. Body and Signature are JSON base64
// values because they are byte slices. Nonce is preserved for executor/Hub
// replay handling; VerifySignedEnvelope intentionally does not track it.
type ExecutorEnvelope struct {
	Version       int       `json:"version"`
	Audience      string    `json:"audience"`
	Role          string    `json:"role"`
	ManifestDigest string    `json:"manifest_digest"`
	BodyDigest    string    `json:"body_digest"`
	Nonce         string    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
	Body          []byte    `json:"body"`
	Signature     []byte    `json:"signature"`
}

// SignedEnvelope is retained as the descriptive name for ExecutorEnvelope.
type SignedEnvelope = ExecutorEnvelope

// CanonicalSigningBytes returns deterministic JSON for every authority-bearing
// field and the body content binding. Signature is deliberately excluded.
func (e *ExecutorEnvelope) CanonicalSigningBytes() ([]byte, error) {
	if e == nil {
		return nil, errors.New("envelope: missing envelope")
	}
	if err := validateEnvelopeFields(e); err != nil {
		return nil, err
	}
	canonical := envelopeSigningDocument{
		Version:        e.Version,
		Audience:       e.Audience,
		Role:           e.Role,
		ManifestDigest: e.ManifestDigest,
		BodyDigest:     e.BodyDigest,
		Nonce:          e.Nonce,
		ExpiresAt:      e.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Body:           e.Body,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, errors.New("envelope: canonical encoding failed")
	}
	return encoded, nil
}

// CanonicalBytes is an alias with a shorter name for callers that need the
// exact bytes signed by BuildSignedEnvelope.
func (e *ExecutorEnvelope) CanonicalBytes() ([]byte, error) {
	return e.CanonicalSigningBytes()
}

// CanonicalSigningBytes returns the bytes that are signed for an envelope.
func CanonicalSigningBytes(e *ExecutorEnvelope) ([]byte, error) {
	return e.CanonicalSigningBytes()
}

type envelopeSigningDocument struct {
	Version        int    `json:"version"`
	Audience       string `json:"audience"`
	Role           string `json:"role"`
	ManifestDigest string `json:"manifest_digest"`
	BodyDigest     string `json:"body_digest"`
	Nonce          string `json:"nonce"`
	ExpiresAt      string `json:"expires_at"`
	Body           []byte `json:"body"`
}

// BuildSignedEnvelope validates authority fields and signs a copy of body
// with Ed25519. The supplied clock is explicit so callers and tests can make
// expiry deterministic.
func BuildSignedEnvelope(
	manifestDigest, role, audience, nonce string,
	expiresAt time.Time,
	body []byte,
	signer ed25519.PrivateKey,
	now time.Time,
) (*ExecutorEnvelope, error) {
	if err := validateRequiredField(manifestDigest, "manifest digest"); err != nil {
		return nil, err
	}
	if !validDigest(manifestDigest) {
		return nil, errors.New("envelope: invalid manifest digest")
	}
	if err := validateRequiredField(role, "role"); err != nil {
		return nil, err
	}
	if err := validateRequiredField(audience, "audience"); err != nil {
		return nil, err
	}
	if err := validateRequiredField(nonce, "nonce"); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("envelope: body is required")
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("envelope: invalid signer")
	}
	if err := validateExpiry(expiresAt, now); err != nil {
		return nil, err
	}

	envelope := &ExecutorEnvelope{
		Version:        EnvelopeVersion,
		Audience:       audience,
		Role:           role,
		ManifestDigest: manifestDigest,
		BodyDigest:     digestBytes(body),
		Nonce:          nonce,
		ExpiresAt:      expiresAt.UTC(),
		Body:           append([]byte(nil), body...),
	}
	canonical, err := envelope.CanonicalSigningBytes()
	if err != nil {
		return nil, err
	}
	envelope.Signature = ed25519.Sign(signer, canonical)
	return envelope, nil
}

// VerifySignedEnvelope validates schema, expiry, body digest, and the
// detached Ed25519 signature. It does not accept, reject, or remember nonce
// replays; nonce replay policy belongs to the Hub/executor.
func VerifySignedEnvelope(envelope *ExecutorEnvelope, publicKey ed25519.PublicKey, now time.Time) error {
	if envelope == nil {
		return errors.New("envelope: missing envelope")
	}
	if err := validateEnvelope(envelope, now); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("envelope: invalid verifier key")
	}
	canonical, err := envelope.CanonicalSigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, envelope.Signature) {
		return errors.New("envelope: invalid signature")
	}
	return nil
}

// EnvelopeClient posts signed envelopes to the fixed Hub route. BaseURL must
// be the Hub origin (no path, query, fragment, or userinfo). HTTPClient and
// Clock are injectable for deterministic offline tests.
type EnvelopeClient struct {
	BaseURL               string
	Signer                ed25519.PrivateKey
	OperatorSessionCookie string
	HTTPClient            *http.Client
	Clock                 func() time.Time
}

// NewEnvelopeClient constructs a client using the default HTTP client and
// wall-clock unless the caller replaces HTTPClient or Clock for testing.
func NewEnvelopeClient(baseURL string, signer ed25519.PrivateKey) *EnvelopeClient {
	return &EnvelopeClient{BaseURL: baseURL, Signer: signer}
}

// Submit builds and posts one signed envelope to /operator/executor-envelope.
// It returns successful response bytes without logging or interpreting them.
// Nonce replay is deliberately not handled here; the future Hub/executor owns
// that policy.
func (c *EnvelopeClient) Submit(
	ctx context.Context,
	manifestDigest, role, audience, nonce string,
	expiresAt time.Time,
	body []byte,
) ([]byte, error) {
	if c == nil {
		return nil, errors.New("envelope: missing client")
	}
	if strings.TrimSpace(c.OperatorSessionCookie) == "" {
		return nil, errors.New("envelope: operator session cookie is required")
	}
	now := time.Now()
	if c.Clock != nil {
		now = c.Clock()
	}
	envelope, err := BuildSignedEnvelope(manifestDigest, role, audience, nonce, expiresAt, body, c.Signer, now)
	if err != nil {
		return nil, err
	}
	requestBody, err := json.Marshal(envelope)
	if err != nil {
		return nil, errors.New("envelope: request encoding failed")
	}
	endpoint, err := fixedEnvelopeURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, errors.New("envelope: request creation failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cookie", c.OperatorSessionCookie)

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	// A redirect could move an otherwise fixed-path signed request to a direct
	// executor or another origin. Preserve the injected transport/timeouts but
	// never follow redirects for this security-sensitive route.
	client := *httpClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("envelope: submit request failed")
	}
	if response == nil {
		return nil, errors.New("envelope: submit request returned no response")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("envelope: Hub returned status %d", response.StatusCode)
	}

	limited := io.LimitReader(response.Body, int64(MaxEnvelopeResponseBytes)+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("envelope: response read failed")
	}
	if len(responseBody) > MaxEnvelopeResponseBytes {
		return nil, errors.New("envelope: response exceeds 1 MiB")
	}
	return responseBody, nil
}

func validateEnvelope(envelope *ExecutorEnvelope, now time.Time) error {
	if err := validateEnvelopeFields(envelope); err != nil {
		return err
	}
	if err := validateExpiry(envelope.ExpiresAt, now); err != nil {
		return err
	}
	if len(envelope.Signature) != ed25519.SignatureSize {
		return errors.New("envelope: invalid signature")
	}
	return nil
}

func validateEnvelopeFields(envelope *ExecutorEnvelope) error {
	if envelope.Version != EnvelopeVersion {
		return errors.New("envelope: unsupported version")
	}
	if err := validateRequiredField(envelope.Audience, "audience"); err != nil {
		return err
	}
	if err := validateRequiredField(envelope.Role, "role"); err != nil {
		return err
	}
	if err := validateRequiredField(envelope.ManifestDigest, "manifest digest"); err != nil {
		return err
	}
	if !validDigest(envelope.ManifestDigest) {
		return errors.New("envelope: invalid manifest digest")
	}
	if err := validateRequiredField(envelope.BodyDigest, "body digest"); err != nil {
		return err
	}
	if !validDigest(envelope.BodyDigest) {
		return errors.New("envelope: invalid body digest")
	}
	if err := validateRequiredField(envelope.Nonce, "nonce"); err != nil {
		return err
	}
	if len(envelope.Body) == 0 {
		return errors.New("envelope: body is required")
	}
	if digestBytes(envelope.Body) != envelope.BodyDigest {
		return errors.New("envelope: body digest mismatch")
	}
	if _, err := envelope.ExpiresAt.MarshalJSON(); err != nil {
		return errors.New("envelope: invalid expiry")
	}
	return nil
}

func validateRequiredField(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("envelope: %s is required", name)
	}
	return nil
}

func validateExpiry(expiresAt, now time.Time) error {
	if expiresAt.IsZero() {
		return errors.New("envelope: expiry is required")
	}
	if _, err := expiresAt.MarshalJSON(); err != nil {
		return errors.New("envelope: invalid expiry")
	}
	if !expiresAt.After(now) {
		return errors.New("envelope: expiry is not in the future")
	}
	if expiresAt.Sub(now) > MaxEnvelopeTTL {
		return errors.New("envelope: expiry exceeds maximum TTL")
	}
	return nil
}

func validDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	hexValue := strings.TrimPrefix(value, prefix)
	if len(hexValue) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(hexValue)
	return err == nil && hexValue == strings.ToLower(hexValue)
}

func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func fixedEnvelopeURL(rawBaseURL string) (string, error) {
	parsed, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", errors.New("envelope: invalid Hub base URL")
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("envelope: Hub base URL must use HTTP or HTTPS")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("envelope: Hub base URL must include a host")
	}
	if parsed.User != nil {
		return "", errors.New("envelope: Hub base URL must not include userinfo")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("envelope: Hub base URL must be an origin")
	}
	if parsed.RawPath != "" && parsed.RawPath != "/" {
		return "", errors.New("envelope: Hub base URL must be an origin")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || strings.ContainsRune(rawBaseURL, '?') {
		return "", errors.New("envelope: Hub base URL must not include a query")
	}
	if parsed.Fragment != "" || strings.ContainsRune(rawBaseURL, '#') {
		return "", errors.New("envelope: Hub base URL must not include a fragment")
	}
	if parsed.Opaque != "" {
		return "", errors.New("envelope: Hub base URL must be an origin")
	}
	parsed.Path = executorEnvelopePath
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.ForceQuery = false
	return parsed.String(), nil
}
