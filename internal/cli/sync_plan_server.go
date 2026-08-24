package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	planSchemaVersion       = "skret-plan/v1"
	defaultPlanListen       = "127.0.0.1:8080"
	defaultPlanMaxBodyBytes = int64(1 << 20)
	maxPlanMaxBodyBytes     = int64(1 << 20)
	syncPlanHandlerTimeout  = 2 * time.Second
	maxPlanStringBytes      = 256
	maxPlanEntries          = 128
	maxPlanJSONDepth        = 32
	maxPlanObjectKeys       = 128
)

var errInvalidSyncPlan = errors.New("invalid plan request")

// SyncPlanSelector identifies a names-only source selection. It deliberately
// has no value-bearing, credential-bearing, mount, or environment fields.
type SyncPlanSelector struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// SyncPlanRule describes one metadata-only target action. It deliberately has
// no secret value or provider credential payload.
type SyncPlanRule struct {
	Target string `json:"target"`
	Action string `json:"action"`
}

// SyncPlanRequest is the complete skret-plan/v1 request. All fields are
// required; JSON decoding is strict and the wire representation must equal
// json.Marshal(request) byte-for-byte.
type SyncPlanRequest struct {
	SchemaVersion string             `json:"schema_version"`
	OperationID   string             `json:"operation_id"`
	Namespace     string             `json:"namespace"`
	Environment   string             `json:"environment"`
	Selectors     []SyncPlanSelector `json:"selectors"`
	Rules         []SyncPlanRule     `json:"rules"`
}

// SyncPlanResponse contains only names-only selectors/rules and metadata. The
// digest fields are SHA-256 values over deterministic canonical JSON bytes.
type SyncPlanResponse struct {
	SchemaVersion string             `json:"schema_version"`
	OperationID   string             `json:"operation_id"`
	Namespace     string             `json:"namespace"`
	Environment   string             `json:"environment"`
	Selectors     []SyncPlanSelector `json:"selectors"`
	Rules         []SyncPlanRule     `json:"rules"`
	PayloadSHA256 string             `json:"payload_sha256"`
	PlanSHA256    string             `json:"plan_sha256"`
}

// Lower-case aliases keep focused package tests concise while the exported
// structs make the contract inspectable by integration tests.
type syncPlanSelector = SyncPlanSelector
type syncPlanRule = SyncPlanRule
type syncPlanRequest = SyncPlanRequest
type syncPlanResponse = SyncPlanResponse

type syncPlanServerOptions struct {
	listen       string
	maxBodyBytes int64
}

func newSyncPlanServerCmd() *cobra.Command {
	o := &syncPlanServerOptions{
		listen:       defaultPlanListen,
		maxBodyBytes: defaultPlanMaxBodyBytes,
	}
	cmd := &cobra.Command{
		Use:   "plan-server",
		Short: "Serve a private metadata-only sync planner",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(o.listen) == "" {
				return errors.New("plan-server: listen address is required")
			}
			if o.maxBodyBytes <= 0 || o.maxBodyBytes > maxPlanMaxBodyBytes {
				return errors.New("plan-server: max body size is out of bounds")
			}
			return runSyncPlanServer(cmd.Context(), o.listen, o.maxBodyBytes)
		},
	}
	cmd.Flags().StringVar(&o.listen, "listen", o.listen, "listen address")
	cmd.Flags().Int64Var(&o.maxBodyBytes, "max-body-bytes", o.maxBodyBytes, "maximum request body size")
	return cmd
}

func runSyncPlanServer(ctx context.Context, listen string, maxBodyBytes int64) error {
	handler := newSyncPlanServerHandler(maxBodyBytes)
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: syncPlanHandlerTimeout,
		ReadTimeout:       syncPlanHandlerTimeout,
		WriteTimeout:      syncPlanHandlerTimeout,
		IdleTimeout:       syncPlanHandlerTimeout,
	}

	shutdown := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), syncPlanHandlerTimeout)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-shutdown:
		}
	}()
	defer close(shutdown)

	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("plan-server: serve failed: %w", err)
}

func newSyncPlanServerHandler(maxBodyBytes int64) http.Handler {
	return newSyncPlanServerHandlerWithTimeout(maxBodyBytes, syncPlanHandlerTimeout)
}

func newSyncPlanServerHandlerWithTimeout(maxBodyBytes int64, timeout time.Duration) http.Handler {
	if maxBodyBytes <= 0 || maxBodyBytes > maxPlanMaxBodyBytes {
		maxBodyBytes = defaultPlanMaxBodyBytes
	}
	if timeout <= 0 {
		timeout = syncPlanHandlerTimeout
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSyncPlanRequest(w, r, maxBodyBytes)
	})
	timeoutHandler := http.TimeoutHandler(mux, timeout, `{"error":"request timeout"}`)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		timeoutHandler.ServeHTTP(w, r)
	})
}

func serveSyncPlanRequest(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) {
	if r.Context().Err() != nil {
		writeSyncPlanError(w, http.StatusRequestTimeout)
		return
	}
	if r.URL.RawQuery != "" {
		writeSyncPlanError(w, http.StatusNotFound)
		return
	}

	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			writeSyncPlanMethodError(w, http.MethodGet)
			return
		}
		writeSyncPlanJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
		return
	case "/v1/plan":
		if r.Method != http.MethodPost {
			writeSyncPlanMethodError(w, http.MethodPost)
			return
		}
		if !hasJSONContentType(r) {
			writeSyncPlanError(w, http.StatusUnsupportedMediaType)
			return
		}
		serveSyncPlanPost(w, r, maxBodyBytes)
		return
	default:
		writeSyncPlanError(w, http.StatusNotFound)
		return
	}
}

func serveSyncPlanPost(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) {
	if r.ContentLength > maxBodyBytes {
		writeSyncPlanError(w, http.StatusRequestEntityTooLarge)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeSyncPlanError(w, http.StatusBadRequest)
		return
	}
	if int64(len(raw)) > maxBodyBytes {
		writeSyncPlanError(w, http.StatusRequestEntityTooLarge)
		return
	}
	if r.Context().Err() != nil {
		writeSyncPlanError(w, http.StatusRequestTimeout)
		return
	}

	request, err := decodeSyncPlanRequest(raw)
	if err != nil {
		writeSyncPlanError(w, http.StatusBadRequest)
		return
	}

	payloadDigest := syncPlanSHA256Hex(raw)
	planBytes, err := canonicalSyncPlan(request)
	if err != nil {
		writeSyncPlanError(w, http.StatusInternalServerError)
		return
	}
	response := SyncPlanResponse{
		SchemaVersion: request.SchemaVersion,
		OperationID:   request.OperationID,
		Namespace:     request.Namespace,
		Environment:   request.Environment,
		Selectors:     request.Selectors,
		Rules:         request.Rules,
		PayloadSHA256: payloadDigest,
		PlanSHA256:    syncPlanSHA256Hex(planBytes),
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		writeSyncPlanError(w, http.StatusInternalServerError)
		return
	}
	writeSyncPlanJSON(w, http.StatusOK, encoded)
}

func decodeSyncPlanRequest(raw []byte) (SyncPlanRequest, error) {
	var request SyncPlanRequest
	if err := rejectDuplicatePlanFields(raw); err != nil {
		return request, errInvalidSyncPlan
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errInvalidSyncPlan
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return request, errInvalidSyncPlan
	}
	if !validSyncPlanRequest(request) {
		return request, errInvalidSyncPlan
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return request, errInvalidSyncPlan
	}
	return request, nil
}

func validSyncPlanRequest(request SyncPlanRequest) bool {
	if request.SchemaVersion != planSchemaVersion || !validPlanText(request.OperationID) ||
		!validPlanText(request.Namespace) || !validPlanText(request.Environment) ||
		request.Selectors == nil || request.Rules == nil || len(request.Selectors) > maxPlanEntries ||
		len(request.Rules) > maxPlanEntries {
		return false
	}
	for _, selector := range request.Selectors {
		if !validPlanText(selector.Name) || !validPlanText(selector.Path) {
			return false
		}
	}
	for _, rule := range request.Rules {
		if !validPlanText(rule.Target) || !validPlanText(rule.Action) {
			return false
		}
	}
	return true
}

func validPlanText(value string) bool {
	if value == "" || len(value) > maxPlanStringBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func canonicalSyncPlan(request SyncPlanRequest) ([]byte, error) {
	// The plan digest covers the complete metadata-only plan. It excludes the
	// payload and plan digest fields themselves to avoid self-reference.
	return json.Marshal(request)
}

func rejectDuplicatePlanFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return errInvalidSyncPlan
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errInvalidSyncPlan
	}
	if err := scanPlanObject(decoder, 1); err != nil {
		return errInvalidSyncPlan
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalidSyncPlan
	}
	return nil
}

func scanPlanObject(decoder *json.Decoder, depth int) error {
	if depth > maxPlanJSONDepth {
		return errInvalidSyncPlan
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errInvalidSyncPlan
		}
		key, ok := token.(string)
		if !ok {
			return errInvalidSyncPlan
		}
		if _, exists := seen[key]; exists || len(seen) >= maxPlanObjectKeys {
			return errInvalidSyncPlan
		}
		seen[key] = struct{}{}
		value, err := decoder.Token()
		if err != nil || scanPlanValue(decoder, value, depth+1) != nil {
			return errInvalidSyncPlan
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errInvalidSyncPlan
	}
	return nil
}

func scanPlanArray(decoder *json.Decoder, depth int) error {
	if depth > maxPlanJSONDepth {
		return errInvalidSyncPlan
	}
	for decoder.More() {
		value, err := decoder.Token()
		if err != nil || scanPlanValue(decoder, value, depth+1) != nil {
			return errInvalidSyncPlan
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return errInvalidSyncPlan
	}
	return nil
}

func scanPlanValue(decoder *json.Decoder, value json.Token, depth int) error {
	delimiter, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return scanPlanObject(decoder, depth)
	case '[':
		return scanPlanArray(decoder, depth)
	default:
		return errInvalidSyncPlan
	}
}

func hasJSONContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	return len(values) == 1 && values[0] == "application/json"
}

func syncPlanSHA256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func writeSyncPlanMethodError(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeSyncPlanError(w, http.StatusMethodNotAllowed)
}

func writeSyncPlanError(w http.ResponseWriter, status int) {
	writeSyncPlanJSON(w, status, []byte(`{"error":"invalid request"}`))
}

func writeSyncPlanJSON(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
