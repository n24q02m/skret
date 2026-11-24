package mcp

import (
	"context"
	"crypto/subtle"
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
		result, rpcErr := s.dispatch(&req)
		if notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
		if rpcErr != nil {
			resp.Result = nil
			resp.Error = rpcErr
		}
		writeJSONHTTP(w, http.StatusOK, resp)
	})
	return mux
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
