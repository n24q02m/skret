package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxHTTPRequestBytes int64 = 1 << 20

// ValidateHTTPAddr ensures non-loopback HTTP listeners always carry a bearer token.
func ValidateHTTPAddr(addr, bearerToken string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("skret mcp: invalid http listen address %q: %w", addr, err)
	}
	if isLoopbackHost(host) {
		return nil
	}
	if strings.TrimSpace(bearerToken) == "" {
		return fmt.Errorf("skret mcp: non-loopback http address %q requires --token or SKRET_MCP_TOKEN", addr)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// HTTPHandler returns the Streamable HTTP MCP handler for POST /mcp and GET /healthz.
func (s *Server) HTTPHandler(bearerToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSONHTTP(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if bearerToken != "" && !authorizedBearer(r.Header.Get("Authorization"), bearerToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="skret-mcp"`)
			writeJSONHTTP(w, http.StatusUnauthorized, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeInvalidRequest, Message: "unauthorized"},
			})
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := io.LimitReader(r.Body, maxHTTPRequestBytes+1)
		raw, err := io.ReadAll(body)
		if err != nil {
			writeJSONHTTP(w, http.StatusBadRequest, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeParseError, Message: "failed to read request body"},
			})
			return
		}
		if int64(len(raw)) > maxHTTPRequestBytes {
			writeJSONHTTP(w, http.StatusRequestEntityTooLarge, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeInvalidRequest, Message: "request body too large"},
			})
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSONHTTP(w, http.StatusBadRequest, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: codeParseError, Message: "parse error: invalid JSON"},
			})
			return
		}
		notification := len(req.ID) == 0
		if req.JSONRPC != "2.0" {
			if notification {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			writeJSONHTTP(w, http.StatusBadRequest, rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &rpcError{Code: codeInvalidRequest, Message: `invalid request: jsonrpc must be "2.0"`},
			})
			return
		}
		version, metaErr := s.requestVersion(req.Params)
		stateless := metaErr != nil || version == ProtocolVersionStateless
		if metaErr == nil && version == ProtocolVersionStateless {
			if header := statelessHeaderMismatch(r.Header, &req, version); header != "" {
				id := req.ID
				if notification {
					id = json.RawMessage("null")
				}
				writeJSONHTTP(w, http.StatusBadRequest, rpcResponse{
					JSONRPC: "2.0",
					ID:      id,
					Error: &rpcError{
						Code:    codeHeaderMismatch,
						Message: "header mismatch: " + header + " is missing or does not match the request body",
					},
				})
				return
			}
		}
		result, rpcErr := s.dispatchAs(&req, version, metaErr)
		if notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
		status := http.StatusOK
		if rpcErr != nil {
			resp.Result = nil
			resp.Error = rpcErr
			if stateless {
				status = http.StatusBadRequest
				if rpcErr.Code == codeMethodNotFound {
					status = http.StatusNotFound
				}
			}
		}
		writeJSONHTTP(w, status, resp)
	})
	return mux
}

// statelessHeaderMismatch checks the request headers a 2026-07-28 request
// must carry against its body and returns the name of the first header that
// is missing or disagrees, or "" when all match. Only the header name is
// ever reported, never its value.
func statelessHeaderMismatch(h http.Header, req *rpcRequest, version string) string {
	if v, ok := headerValue(h, "MCP-Protocol-Version"); !ok || v != version {
		return "MCP-Protocol-Version"
	}
	if v, ok := headerValue(h, "Mcp-Method"); !ok || v != req.Method {
		return "Mcp-Method"
	}
	if req.Method == "tools/call" {
		var p callParams
		_ = json.Unmarshal(req.Params, &p) // malformed params are rejected by tools/call itself
		if v, ok := headerValue(h, "Mcp-Name"); !ok || v != p.Name {
			return "Mcp-Name"
		}
	}
	return ""
}

// headerValue reads one request header. A value wrapped in the
// =?base64?...?= sentinel is decoded first; ok is false when the header is
// absent, empty, or carries an undecodable sentinel.
func headerValue(h http.Header, name string) (string, bool) {
	v := h.Get(name)
	if v == "" {
		return "", false
	}
	const prefix, suffix = "=?base64?", "?="
	if strings.HasPrefix(v, prefix) && strings.HasSuffix(v, suffix) && len(v) >= len(prefix)+len(suffix) {
		decoded, err := base64.StdEncoding.DecodeString(v[len(prefix) : len(v)-len(suffix)])
		if err != nil {
			return "", false
		}
		return string(decoded), true
	}
	return v, true
}

// ServeHTTP starts the Streamable HTTP MCP server until ctx is cancelled.
func (s *Server) ServeHTTP(ctx context.Context, addr, bearerToken string) error {
	if err := ValidateHTTPAddr(addr, bearerToken); err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("skret mcp: listen %q: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           s.HTTPHandler(bearerToken),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return <-errCh
	case err := <-errCh:
		return err
	}
}

func authorizedBearer(header, expected string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func writeJSONHTTP(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
