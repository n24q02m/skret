// Package mcp implements the skret-mcp server: an MCP (Model Context
// Protocol) stdio server that exposes a skret project's secrets to agent
// harnesses. Read tools are always available; write tools are gated behind
// mcp.allow_write in .skret.yaml (default off) and reads through the local
// provider are appended to the same audit trail mutations use.
//
// Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout, one message
// per line, exactly as the MCP stdio transport specifies. All diagnostics
// go to stderr; stdout carries only protocol messages.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/n24q02m/skret/internal/config"
	"github.com/n24q02m/skret/pkg/skret"
)

// ServerName is the serverInfo.name reported during initialize.
const ServerName = "skret-mcp"

// ProtocolVersionLatest is the newest MCP protocol version this server
// speaks. During initialize the server echoes the client's requested
// version when supported, else answers with this one.
const ProtocolVersionLatest = "2025-06-18"

// protocolVersionsSupported is the closed set of protocol versions accepted
// from a client. The initialize response always names one of these, so a
// client can rely on the negotiated semantics.
var protocolVersionsSupported = map[string]bool{
	"2024-11-05":          true,
	"2025-03-26":          true,
	ProtocolVersionLatest: true,
}

// JSON-RPC 2.0 error codes used by this server.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Options configures a Server. WorkDir/Env/Provider/Path mirror the CLI
// global flags; Version is reported in serverInfo (wired from
// internal/version at build time).
type Options struct {
	WorkDir  string
	Env      string
	Provider string
	Path     string
	Version  string
}

// Server serves MCP requests for one discovered skret project.
type Server struct {
	opts    Options
	cfg     *config.Config
	cfgPath string

	mu      sync.Mutex
	clients map[string]*skret.Client
}

// New discovers and loads the .skret.yaml for opts.WorkDir and validates
// the MCP policy (allowed_envs). No provider is constructed here: clients
// are created lazily per requested environment so a broken credential in
// one environment never blocks serving the others.
func New(opts Options) (*Server, error) {
	workDir := opts.WorkDir
	cfgPath, err := config.Discover(workDir)
	if err != nil {
		return nil, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, "skret-mcp: failed to discover configuration", err),
			"run skret init (or skret setup) in the project directory, or start skret-mcp with --workdir pointing at a directory containing .skret.yaml")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, skret.NewError(skret.ExitConfigError, "skret-mcp: failed to load configuration", err)
	}

	s := &Server{opts: opts, cfg: cfg, cfgPath: cfgPath, clients: map[string]*skret.Client{}}

	// Fail at startup, not on the first tool call, when the requested
	// default environment is outside mcp.allowed_envs: the operator asked
	// for a server that cannot legally serve its own default.
	if env := s.startupEnv(); env != "" && !s.envAllowed(env) {
		return nil, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, fmt.Sprintf("skret-mcp: environment %q is not in mcp.allowed_envs", env), nil),
			"add "+env+" to mcp.allowed_envs in "+cfgPath+", or start with a different --env")
	}
	return s, nil
}

// startupEnv resolves the environment the server is pinned to by --env
// (empty string means "the config's default"; tool calls may still override).
// cfg is always non-nil after New.
func (s *Server) startupEnv() string {
	if s.opts.Env != "" {
		return s.opts.Env
	}
	return s.cfg.DefaultEnv
}

// allowWrite reports whether mutating tools are enabled (mcp.allow_write,
// default false).
func (s *Server) allowWrite() bool {
	return s.cfg.MCP != nil && s.cfg.MCP.AllowWrite
}

// envAllowed reports whether the MCP policy permits env. An empty
// mcp.allowed_envs means every declared environment.
func (s *Server) envAllowed(env string) bool {
	if s.cfg.MCP == nil || len(s.cfg.MCP.AllowedEnvs) == 0 {
		return true
	}
	for _, name := range s.cfg.MCP.AllowedEnvs {
		if name == env {
			return true
		}
	}
	return false
}

// allowedEnvs lists the environments the server may access, sorted: the
// mcp.allowed_envs filter when set, else every declared environment.
func (s *Server) allowedEnvs() []string {
	names := make([]string, 0, len(s.cfg.Environments))
	if s.cfg.MCP != nil && len(s.cfg.MCP.AllowedEnvs) > 0 {
		names = append(names, s.cfg.MCP.AllowedEnvs...)
	} else {
		for name := range s.cfg.Environments {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// envNames lists every declared environment name, sorted (unfiltered -- the
// raw config view skret_env applies its filter to).
func (s *Server) envNames() []string {
	names := make([]string, 0, len(s.cfg.Environments))
	for name := range s.cfg.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// defaultEnv picks the environment a tool call uses when the caller passes
// no env argument: --env, else default_env, else the single declared
// environment (mirroring config.Resolve's precedence).
func (s *Server) defaultEnv() string {
	if s.opts.Env != "" {
		return s.opts.Env
	}
	if s.cfg.DefaultEnv != "" {
		return s.cfg.DefaultEnv
	}
	if len(s.cfg.Environments) == 1 {
		for name := range s.cfg.Environments {
			return name
		}
	}
	return ""
}

// clientFor resolves the environment for a tool call (arg overrides the
// server default), enforces allowed_envs, and returns a cached skret
// client for it.
func (s *Server) clientFor(argEnv string) (*skret.Client, string, error) {
	env := argEnv
	if env == "" {
		env = s.defaultEnv()
	}
	if env == "" {
		return nil, "", skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, "no environment selected", nil),
			"pass an env argument, set default_env in .skret.yaml, or start skret-mcp with --env")
	}
	if !s.envAllowed(env) {
		return nil, env, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, fmt.Sprintf("environment %q is not permitted by mcp.allowed_envs", env), nil),
			"ask the operator to add "+env+" to mcp.allowed_envs in .skret.yaml, or use one of: "+strings.Join(s.allowedEnvs(), ", "))
	}
	if _, ok := s.cfg.Environments[env]; !ok {
		return nil, env, skret.WithRemediation(
			skret.NewError(skret.ExitNotFoundError, fmt.Sprintf("environment %q not found in config", env), nil),
			"declared environments: "+strings.Join(s.envNames(), ", "))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[env]; ok {
		return c, env, nil
	}
	c, err := skret.New(skret.Options{
		WorkDir:  s.opts.WorkDir,
		Env:      env,
		Provider: s.opts.Provider,
		Path:     s.opts.Path,
	})
	if err != nil {
		return nil, env, err
	}
	s.clients[env] = c
	return c, env, nil
}

// Close releases every cached client's provider resources.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for env, c := range s.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(s.clients, env)
	}
	return firstErr
}

// rpcRequest is one inbound JSON-RPC message. ID==nil (field absent) marks
// a notification; "id": null is a (spec-discouraged) request answered with
// a null id.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// rpcResponse is one outbound message. Result and Error are mutually
// exclusive; both omitempty because ping answers with an empty result.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads newline-delimited JSON-RPC messages from r and writes
// responses to w until r is exhausted. Malformed lines get a parse-error
// response and the loop continues with the next line (the transport is
// line-delimited, so the stream resynchronizes at the next newline).
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		s.handleLine(line, w)
	}
	return sc.Err()
}

// handleLine parses and dispatches one message; it never returns an error
// (protocol problems become error responses).
func (s *Server) handleLine(line string, w io.Writer) {
	var req rpcRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		s.write(w, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{
			Code: codeParseError, Message: "parse error: invalid JSON",
		}})
		return
	}
	notification := len(req.ID) == 0
	if req.JSONRPC != "2.0" {
		if notification {
			return
		}
		s.write(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{
			Code: codeInvalidRequest, Message: `invalid request: jsonrpc must be "2.0"`,
		}})
		return
	}

	result, rpcErr := s.dispatch(&req)
	if notification {
		return
	}
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	if rpcErr != nil {
		resp.Result = nil
		resp.Error = rpcErr
	}
	s.write(w, resp)
}

// dispatch routes one request. A non-nil rpcError is a protocol-level
// error; otherwise result is the (possibly isError-flagged) tool result.
func (s *Server) dispatch(req *rpcRequest) (result any, rpcErr *rpcError) {
	switch req.Method {
	case "initialize":
		return s.initialize(req.Params)
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return listToolsResult(), nil
	case "tools/call":
		return s.toolsCall(req.Params)
	case "notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed":
		return nil, nil
	default:
		return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + req.Method}
	}
}

// initializeRequest is the client's initialize params.
type initializeRequest struct {
	ProtocolVersion string `json:"protocolVersion"`
}

// initializeResult is the server's initialize response.
type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions,omitempty"`
}

type capabilities struct {
	Tools *toolsCapability `json:"tools"`
}

type toolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (s *Server) initialize(params json.RawMessage) (any, *rpcError) {
	var req initializeRequest
	if len(params) > 0 {
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
		}
	}
	version := ProtocolVersionLatest
	if protocolVersionsSupported[req.ProtocolVersion] {
		version = req.ProtocolVersion
	}
	slog.Debug("skret-mcp: initialized", "client_protocol", req.ProtocolVersion, "negotiated", version)
	return initializeResult{
		ProtocolVersion: version,
		Capabilities:    capabilities{Tools: &toolsCapability{ListChanged: false}},
		ServerInfo:      serverInfo{Name: ServerName, Version: s.opts.Version},
		Instructions: "Tools expose the skret secret manager for the resolved .skret.yaml environment. " +
			"Secret values are returned only by skret_get; skret_list returns key names only. " +
			"Write tools require mcp.allow_write: true in .skret.yaml (default off).",
	}, nil
}

// write marshals one response and appends the newline delimiter. A marshal
// failure is logged, never propagated: the only marshalable types here are
// plain data.
func (s *Server) write(w io.Writer, resp rpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("skret-mcp: marshal response", "err", err)
		return
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		slog.Debug("skret-mcp: client closed stdout", "err", err)
	}
}
