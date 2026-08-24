package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPlanPayload = `{"schema_version":"skret-plan/v1","operation_id":"op-123","namespace":"knowledgeprism","environment":"candidate","selectors":[{"name":"source/alpha","path":"/alpha"},{"name":"source/beta","path":"/beta"}],"rules":[{"target":"github","action":"upsert"},{"target":"dotenv","action":"upsert"}]}`

func TestSyncPlanServerCommandPreservesSyncFlags(t *testing.T) {
	cmd := newSyncCmd(&GlobalOpts{})

	child, _, err := cmd.Find([]string{"plan-server"})
	require.NoError(t, err)
	require.NotNil(t, child)
	assert.Equal(t, "plan-server", child.Name())
	assert.NotNil(t, child.Flags().Lookup("listen"))
	assert.NotNil(t, child.Flags().Lookup("max-body-bytes"))
	for _, name := range []string{"to", "file", "github-repo", "skip-unchanged", "no-overwrite", "rotate", "dry-run", "format"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "sync flag %q must remain on parent", name)
	}
}

func TestSyncPlanServerValidRequestReturnsDeterministicMetadataOnly(t *testing.T) {
	handler := newSyncPlanServerHandler(1 << 20)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(validPlanPayload))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))
	assert.NotContains(t, res.Body.String(), "values")
	assert.NotContains(t, res.Body.String(), "credentials")
	assert.NotContains(t, res.Body.String(), "mount")
	assert.NotContains(t, res.Body.String(), `"env":`)

	var response syncPlanResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &response))
	assert.Equal(t, planSchemaVersion, response.SchemaVersion)
	assert.Equal(t, "op-123", response.OperationID)
	assert.Equal(t, "knowledgeprism", response.Namespace)
	assert.Equal(t, "candidate", response.Environment)
	assert.Equal(t, []syncPlanSelector{{Name: "source/alpha", Path: "/alpha"}, {Name: "source/beta", Path: "/beta"}}, response.Selectors)
	assert.Equal(t, []syncPlanRule{{Target: "github", Action: "upsert"}, {Target: "dotenv", Action: "upsert"}}, response.Rules)

	payloadSum := sha256.Sum256([]byte(validPlanPayload))
	assert.Equal(t, hex.EncodeToString(payloadSum[:]), response.PayloadSHA256)
	planJSON := `{"schema_version":"skret-plan/v1","operation_id":"op-123","namespace":"knowledgeprism","environment":"candidate","selectors":[{"name":"source/alpha","path":"/alpha"},{"name":"source/beta","path":"/beta"}],"rules":[{"target":"github","action":"upsert"},{"target":"dotenv","action":"upsert"}]}`
	planSum := sha256.Sum256([]byte(planJSON))
	assert.Equal(t, hex.EncodeToString(planSum[:]), response.PlanSHA256)

	assert.JSONEq(t, `{"schema_version":"skret-plan/v1","operation_id":"op-123","namespace":"knowledgeprism","environment":"candidate","selectors":[{"name":"source/alpha","path":"/alpha"},{"name":"source/beta","path":"/beta"}],"rules":[{"target":"github","action":"upsert"},{"target":"dotenv","action":"upsert"}],"payload_sha256":"`+response.PayloadSHA256+`","plan_sha256":"`+response.PlanSHA256+`"}`, res.Body.String())
}

func TestSyncPlanServerHealthz(t *testing.T) {
	handler := newSyncPlanServerHandler(1 << 20)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))

	assert.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))
	assert.Equal(t, `{"status":"ok"}`, res.Body.String())
}

func TestSyncPlanServerRejectsUnsupportedSurface(t *testing.T) {
	handler := newSyncPlanServerHandler(1 << 20)
	cases := []struct {
		name        string
		method      string
		path        string
		contentType string
		want        int
	}{
		{"plan-get", http.MethodGet, "/v1/plan", "application/json", http.StatusMethodNotAllowed},
		{"health-post", http.MethodPost, "/healthz", "application/json", http.StatusMethodNotAllowed},
		{"unknown-route", http.MethodGet, "/v1/other", "application/json", http.StatusNotFound},
		{"unsupported-content-type", http.MethodPost, "/v1/plan", "text/plain", http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, strings.NewReader(validPlanPayload))
			req.Header.Set("Content-Type", tc.contentType)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			assert.Equal(t, tc.want, res.Code)
			assert.NotContains(t, res.Body.String(), "op-123")
		})
	}
}

func TestSyncPlanServerRejectsMalformedOrNoncanonicalRequests(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unknown-field", strings.Replace(validPlanPayload, `,"rules"`, `,"unexpected":"x","rules"`, 1)},
		{"duplicate-field", strings.Replace(validPlanPayload, `,"rules"`, `,"operation_id":"op-456","rules"`, 1)},
		{"missing-field", strings.Replace(validPlanPayload, `,"rules":[{"target":"github","action":"upsert"},{"target":"dotenv","action":"upsert"}]`, "", 1)},
		{"nested-duplicate-field", strings.Replace(validPlanPayload, `{"name":"source/alpha","path":"/alpha"}`, `{"name":"source/alpha","path":"/alpha","path":"/beta"}`, 1)},
		{"nested-unknown-field", strings.Replace(validPlanPayload, `{"name":"source/alpha","path":"/alpha"}`, `{"name":"source/alpha","path":"/alpha","value":"secret-value"}`, 1)},
		{"noncanonical-whitespace", " {\"schema_version\":\"skret-plan/v1\",\"operation_id\":\"op-123\",\"namespace\":\"knowledgeprism\",\"environment\":\"candidate\",\"selectors\":[{\"name\":\"source/alpha\",\"path\":\"/alpha\"},{\"name\":\"source/beta\",\"path\":\"/beta\"}],\"rules\":[{\"target\":\"github\",\"action\":\"upsert\"},{\"target\":\"dotenv\",\"action\":\"upsert\"}]}"},
		{"noncanonical-escape", strings.Replace(validPlanPayload, "op-123", "op-\\u0031\\u0032\\u0033", 1)},
		{"values-field", strings.Replace(validPlanPayload, `,"rules"`, `,"values":["secret-value"],"rules"`, 1)},
		{"credentials-field", strings.Replace(validPlanPayload, `,"rules"`, `,"credentials":["secret-value"],"rules"`, 1)},
		{"mount-field", strings.Replace(validPlanPayload, `,"rules"`, `,"mount":"/tmp","rules"`, 1)},
		{"env-field", strings.Replace(validPlanPayload, `,"rules"`, `,"env":{"SECRET":"secret-value"},"rules`, 1)},
		{"github-credential", strings.Replace(validPlanPayload, `,"rules"`, `,"GITHUB_TOKEN":"redacted-token","rules`, 1)},
		{"cloudflare-credential", strings.Replace(validPlanPayload, `,"rules"`, `,"CLOUDFLARE_API_TOKEN":"redacted-token","rules`, 1)},
		{"aws-credential", strings.Replace(validPlanPayload, `,"rules"`, `,"AWS_ACCESS_KEY_ID":"redacted-token","rules`, 1)},
		{"aws-secret-credential", strings.Replace(validPlanPayload, `,"rules"`, `,"AWS_SECRET_ACCESS_KEY":"redacted-token","rules`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newSyncPlanServerHandler(1 << 20)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			assert.Equal(t, http.StatusBadRequest, res.Code)
			assert.NotContains(t, res.Body.String(), "secret-value")
		})
	}
}

func TestSyncPlanServerRejectsObjectWithTooManyKeys(t *testing.T) {
	var body strings.Builder
	body.WriteByte('{')
	for i := 0; i <= maxPlanObjectKeys; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString(`"key-`)
		body.WriteString(strconv.Itoa(i))
		body.WriteString(`":null`)
	}
	body.WriteByte('}')

	require.Error(t, rejectDuplicatePlanFields([]byte(body.String())))
}

func TestSyncPlanServerRejectsOversizedBody(t *testing.T) {
	body := strings.Repeat("x", 64)
	handler := newSyncPlanServerHandler(int64(len(body) - 1))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, res.Code)
	assert.NotContains(t, res.Body.String(), body)
}

func TestSyncPlanServerUsesBoundedTimeout(t *testing.T) {
	assert.Greater(t, syncPlanHandlerTimeout, time.Duration(0))
	assert.LessOrEqual(t, syncPlanHandlerTimeout, 5*time.Second)

	handler := newSyncPlanServerHandler(1 << 20)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", strings.NewReader(validPlanPayload))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req.WithContext(ctx))

	assert.NotEqual(t, http.StatusOK, res.Code)
	assert.NotContains(t, res.Body.String(), "op-123")
}

func TestSyncPlanServerTimeoutResponseIsJSON(t *testing.T) {
	handler := newSyncPlanServerHandlerWithTimeout(1<<20, time.Millisecond)
	reader := newBlockingPlanReader()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/plan", io.NopCloser(reader))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		handler.ServeHTTP(res, req)
		close(done)
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start reading request body")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		close(reader.release)
		t.Fatal("timeout handler did not return")
	}
	close(reader.release)

	assert.Equal(t, http.StatusServiceUnavailable, res.Code)
	assert.Equal(t, "application/json", res.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"error":"request timeout"}`, res.Body.String())
}

type blockingPlanReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingPlanReader() *blockingPlanReader {
	return &blockingPlanReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (reader *blockingPlanReader) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.release
	return 0, io.EOF
}
