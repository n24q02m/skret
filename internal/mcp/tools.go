package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/n24q02m/skret/internal/provider"
	"github.com/n24q02m/skret/internal/provider/local"
	"github.com/n24q02m/skret/pkg/skret"
)

// content is one MCP content block. Only text content is produced.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the MCP tools/call result. isError marks a tool execution
// failure (per the MCP spec these are results, not protocol-level errors).
// ResultType and Meta are set for 2026-07-28 requests only.
type toolResult struct {
	ResultType string         `json:"resultType,omitempty"`
	Content    []content      `json:"content"`
	IsError    bool           `json:"isError,omitempty"`
	Meta       map[string]any `json:"_meta,omitempty"`
}

// toolDesc is one tools/list entry.
type toolDesc struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// textResult wraps a successful text payload.
func textResult(text string) toolResult {
	return toolResult{Content: []content{{Type: "text", Text: text}}}
}

// toolErr renders a failed tool execution: message plus the remediation
// hint when one is attached, so an agent sees the copy-pasteable fix. The
// text is redacted of every secret value loaded in the session.
func (s *Server) toolErr(err error) toolResult {
	msg := err.Error()
	if hint := skret.RemediationOf(err); hint != "" {
		msg += "\nremediation: " + hint
	}
	return toolResult{Content: []content{{Type: "text", Text: s.redact(msg)}}, IsError: true}
}

// confirmErr refuses a write call that omits the per-call confirmation
// argument. The store is never touched.
func confirmErr(tool string) error {
	return deny(reasonConfirmRequired, skret.WithRemediation(
		skret.NewError(skret.ExitValidationError, tool+": per-call confirmation missing", nil),
		`add "confirm": true to the tool arguments (mirrors the CLI --confirm flag); nothing was mutated`))
}

// argConfirm reads the per-call write confirmation. Only a JSON boolean
// true counts; a string "true" or any other type is not a confirmation.
func argConfirm(args map[string]any) bool {
	v, ok := args["confirm"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// argErr refuses a call with a missing or wrong-typed argument.
func argErr(tool, argsShape string) error {
	return deny(reasonInvalidArguments, skret.WithRemediation(
		skret.NewError(skret.ExitValidationError, tool+": key or value argument missing or not a string", nil),
		`pass arguments like {"key": "<name>", "value": "<value>"}; exact shape: `+argsShape))
}

// Tool argument schemas. env is optional everywhere it appears (the server
// falls back to its resolved default environment); key/value are required
// where the operation needs them.
const (
	schemaEmpty = `{"type":"object","properties":{}}`

	schemaList = `{"type":"object","properties":{"env":{"type":"string","description":"Target environment name. Defaults to the server's resolved environment (default_env in .skret.yaml)."}}}`

	schemaGet = `{"type":"object","properties":{` +
		`"key":{"type":"string","description":"Secret key name."},` +
		`"env":{"type":"string","description":"Target environment name; defaults to the server's resolved environment."}` +
		`},"required":["key"]}`

	schemaSet = `{"type":"object","properties":{` +
		`"key":{"type":"string","description":"Secret key name."},` +
		`"value":{"type":"string","description":"Secret value to store."},` +
		`"confirm":{"type":"boolean","description":"Per-call write confirmation: must be true. Mirrors the CLI --confirm flag."},` +
		`"env":{"type":"string","description":"Target environment name; defaults to the server's resolved environment."}` +
		`},"required":["key","value","confirm"]}`

	schemaDelete = `{"type":"object","properties":{` +
		`"key":{"type":"string","description":"Secret key name."},` +
		`"confirm":{"type":"boolean","description":"Per-call write confirmation: must be true. Mirrors the CLI --confirm flag."},` +
		`"env":{"type":"string","description":"Target environment name; defaults to the server's resolved environment."}` +
		`},"required":["key","confirm"]}`
)

// tools lists every tool this server implements, in canonical order. The
// names match config.MCPToolNames, the set mcp.allowed_tools accepts.
func tools() []toolDesc {
	return []toolDesc{
		{
			Name: "skret_list",
			Description: "List skret secret key names for an environment. Names only -- secret values are structurally excluded. " +
				"Output: JSON array of key names.",
			InputSchema: json.RawMessage(schemaList),
		},
		{
			Name:        "skret_get",
			Description: "Read one skret secret value by key. This is the only tool that returns secret values. Output: the raw value as text.",
			InputSchema: json.RawMessage(schemaGet),
		},
		{
			Name:        "skret_env",
			Description: "List the skret environments this server may access. Output: JSON object {environments: [...], default_env}.",
			InputSchema: json.RawMessage(schemaEmpty),
		},
		{
			Name: "skret_status",
			Description: "Report skret-mcp server health: resolved environment, provider, config file, write policy. No network calls, no secret values. " +
				"Output: JSON object.",
			InputSchema: json.RawMessage(schemaEmpty),
		},
		{
			Name:        "skret_doctor",
			Description: "Alias for skret_status.",
			InputSchema: json.RawMessage(schemaEmpty),
		},
		{
			Name:        "skret_set",
			Description: "Create or update a skret secret. Requires mcp.allow_write: true in .skret.yaml (default off) AND a per-call \"confirm\": true argument.",
			InputSchema: json.RawMessage(schemaSet),
		},
		{
			Name:        "skret_delete",
			Description: "Delete a skret secret. Requires mcp.allow_write: true in .skret.yaml (default off) AND a per-call \"confirm\": true argument.",
			InputSchema: json.RawMessage(schemaDelete),
		},
		{
			Name:        "skret_rotate",
			Description: "Replace a skret secret's value with an explicit new value (recorded as a rotation in the audit trail). Requires mcp.allow_write: true in .skret.yaml (default off) AND a per-call \"confirm\": true argument.",
			InputSchema: json.RawMessage(schemaSet),
		},
	}
}

// visibleTools is the tools/list payload in canonical order: every tool,
// or with mcp.allowed_tools set the tools a call may use (see
// toolVisible). It is never nil, so an empty set is sent as [] rather than
// null.
func (s *Server) visibleTools() []toolDesc {
	all := tools()
	out := make([]toolDesc, 0, len(all))
	for _, d := range all {
		if s.toolVisible(d.Name) {
			out = append(out, d)
		}
	}
	return out
}

// visibleToolNames lists the names of visibleTools.
func (s *Server) visibleToolNames() []string {
	visible := s.visibleTools()
	names := make([]string, 0, len(visible))
	for _, d := range visible {
		names = append(names, d.Name)
	}
	return names
}

// callParams is the tools/call request params.
type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// toolHandler runs one tool and returns its text result. A returned error
// becomes an isError result; a denial also marks the audit record denied.
type toolHandler func(*Server, *callState) (string, error)

// toolHandlers maps each tool name to its handler.
var toolHandlers = map[string]toolHandler{
	"skret_list":   (*Server).toolList,
	"skret_get":    (*Server).toolGet,
	"skret_env":    (*Server).toolEnvs,
	"skret_status": (*Server).toolStatus,
	"skret_doctor": (*Server).toolStatus,
	"skret_set":    (*Server).toolSet,
	"skret_delete": (*Server).toolDelete,
	"skret_rotate": (*Server).toolRotate,
}

// toolsCall dispatches a tools/call. Structural failures (unknown tool,
// malformed arguments) are protocol errors; execution outcomes (including
// policy denial and missing keys) are isError results per the MCP spec.
// Either way the call gets exactly one audit record.
func (s *Server) toolsCall(params json.RawMessage) (*toolResult, *rpcError) {
	var p callParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, s.refuseCall(&callState{tool: p.Name}, reasonInvalidParams,
				&rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()})
		}
	}
	if p.Name == "" {
		return nil, s.refuseCall(&callState{}, reasonInvalidParams,
			&rpcError{Code: codeInvalidParams, Message: "invalid params: name is required"})
	}
	handler, ok := toolHandlers[p.Name]
	if !ok {
		return nil, s.refuseCall(&callState{tool: p.Name}, reasonUnknownTool,
			&rpcError{Code: codeInvalidParams, Message: "unknown tool: " + p.Name})
	}
	args := p.Arguments
	if args == nil {
		args = map[string]any{}
	}
	st := &callState{tool: p.Name, args: args}

	// A value sent to a write tool is a secret from this point on, even if
	// the call is refused below.
	if isWriteTool(p.Name) {
		if v, ok := argString(args, "value"); ok {
			s.redactor.Add(v)
		}
	}

	text, err := s.runTool(st, handler)
	res := textResult(text)
	if auditErr := s.recordCall(st, err); auditErr != nil {
		res = s.toolErr(auditErr)
	} else if err != nil {
		res = s.toolErr(err)
	}
	return &res, nil
}

// runTool applies the tool-level policy and then runs the handler, which
// applies the argument, environment and key policy before any provider
// call.
func (s *Server) runTool(st *callState, handler toolHandler) (string, error) {
	if err := s.toolGate(st.tool); err != nil {
		return "", err
	}
	return handler(s, st)
}

// argString reads a string argument; ok is false when absent or not a
// string (a wrong-typed argument is a caller error, surfaced as such).
func argString(args map[string]any, name string) (string, bool) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// argEnv extracts the optional env argument.
func argEnv(args map[string]any) string {
	env, _ := argString(args, "env")
	return env
}

// Tool handlers ---------------------------------------------------------------

// toolList returns the key names (never values) the key policy admits for
// the selected environment. Every listed value is registered for
// redaction. The list read is audited like skret_get so the trail shows
// every MCP access scope.
func (s *Server) toolList(st *callState) (string, error) {
	st.wildcard = true
	if err := s.authorize(st); err != nil {
		return "", err
	}
	c, env, err := s.clientFor(st.env)
	if err != nil {
		return "", err
	}
	secrets, err := c.List(context.Background())
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(secrets))
	for _, sec := range secrets {
		s.redactor.Add(sec.Value)
		if s.keyDecision(sec.Key) == "" {
			names = append(names, sec.Key)
		}
	}
	if err := s.auditRead(c, env, "*"); err != nil {
		return "", err
	}
	return mustJSON(names), nil
}

// toolGet returns one secret's value -- the only path a value takes out of
// the server.
func (s *Server) toolGet(st *callState) (string, error) {
	key, ok := argString(st.args, "key")
	if !ok {
		return "", argErr("skret_get", schemaGet)
	}
	st.keys = []string{key}
	if err := s.authorize(st, key); err != nil {
		return "", err
	}
	c, env, err := s.clientFor(st.env)
	if err != nil {
		return "", err
	}
	sec, err := c.Get(context.Background(), key)
	if err != nil {
		return "", err
	}
	s.redactor.Add(sec.Value)
	if err := s.auditRead(c, env, key); err != nil {
		return "", err
	}
	return sec.Value, nil
}

// envList is the skret_env payload.
type envList struct {
	Environments []string `json:"environments"`
	DefaultEnv   string   `json:"default_env,omitempty"`
}

func (s *Server) toolEnvs(*callState) (string, error) {
	return mustJSON(envList{Environments: s.allowedEnvs(), DefaultEnv: s.defaultEnv()}), nil
}

// statusReport is the skret_status / skret_doctor payload. It reflects
// configuration and policy only -- running it never touches a provider.
// The tool and key policy fields appear only when the operator set them,
// so a config without them reports exactly what it did before.
type statusReport struct {
	OK          bool     `json:"ok"`
	Version     string   `json:"version"`
	Env         string   `json:"env"`
	Provider    string   `json:"provider"`
	Path        string   `json:"path,omitempty"`
	ConfigFile  string   `json:"config_file"`
	AllowWrite  bool     `json:"allow_write"`
	AllowedEnvs []string `json:"allowed_envs"`
	ReadOnly    bool     `json:"read_only"`
	Tools       []string `json:"tools,omitempty"`
	AllowedKeys []string `json:"allowed_keys,omitempty"`
	DeniedKeys  []string `json:"denied_keys,omitempty"`
	AuditLog    string   `json:"audit_log,omitempty"`
}

func (s *Server) toolStatus(*callState) (string, error) {
	env := s.defaultEnv()
	providerName := ""
	var path string
	if e, ok := s.cfg.Environments[env]; ok {
		providerName = e.Provider
		path = e.Path
	}
	report := statusReport{
		OK:          true,
		Version:     s.opts.Version,
		Env:         env,
		Provider:    providerName,
		Path:        path,
		ConfigFile:  s.cfgPath,
		AllowWrite:  s.allowWrite(),
		AllowedEnvs: s.allowedEnvs(),
		ReadOnly:    !s.allowWrite(),
		AuditLog:    s.auditPath,
	}
	if s.toolsPolicySet() {
		report.Tools = s.visibleToolNames()
	}
	if s.cfg.MCP != nil {
		report.AllowedKeys = s.cfg.MCP.AllowedKeys
		report.DeniedKeys = s.cfg.MCP.DeniedKeys
	}
	return mustJSON(report), nil
}

// toolSet creates or updates a secret (write-gated + confirmed per call).
func (s *Server) toolSet(st *callState) (string, error) {
	const shape = `{"key": "<name>", "value": "<value>", "confirm": true}`
	key, keyOK := argString(st.args, "key")
	value, valOK := argString(st.args, "value")
	if !keyOK || !valOK {
		return "", argErr("skret_set", shape)
	}
	c, env, err := s.authorizeWrite(st, "skret_set", key)
	if err != nil {
		return "", err
	}
	if err := c.Set(context.Background(), key, value, provider.SecretMeta{}); err != nil {
		return "", err
	}
	slog.Info("skret-mcp: set", "env", s.redact(env), "key", s.redact(key))
	return fmt.Sprintf("set %s (env %s)", key, env), nil
}

// toolDelete removes a secret (write-gated + confirmed per call).
func (s *Server) toolDelete(st *callState) (string, error) {
	const shape = `{"key": "<name>", "confirm": true}`
	key, ok := argString(st.args, "key")
	if !ok {
		return "", argErr("skret_delete", shape)
	}
	c, env, err := s.authorizeWrite(st, "skret_delete", key)
	if err != nil {
		return "", err
	}
	if err := c.Delete(context.Background(), key); err != nil {
		return "", err
	}
	slog.Info("skret-mcp: delete", "env", s.redact(env), "key", s.redact(key))
	return fmt.Sprintf("deleted %s (env %s)", key, env), nil
}

// toolRotate replaces a secret's value, recorded as a rotation in the
// local provider's audit trail (write-gated + confirmed per call).
// Generation stays with the caller: MCP passes the explicit replacement
// value, exactly like `skret rotate --value`.
func (s *Server) toolRotate(st *callState) (string, error) {
	const shape = `{"key": "<name>", "value": "<new value>", "confirm": true}`
	key, keyOK := argString(st.args, "key")
	value, valOK := argString(st.args, "value")
	if !keyOK || !valOK {
		return "", argErr("skret_rotate", shape)
	}
	c, env, err := s.authorizeWrite(st, "skret_rotate", key)
	if err != nil {
		return "", err
	}
	ctx := local.WithAuditOp(context.Background(), local.AuditOpRotate)
	if err := c.Set(ctx, key, value, provider.SecretMeta{}); err != nil {
		return "", err
	}
	slog.Info("skret-mcp: rotate", "env", s.redact(env), "key", s.redact(key))
	return fmt.Sprintf("rotated %s (env %s)", key, env), nil
}

// authorizeWrite requires the per-call confirmation of a write call, then
// applies the environment and key policy, and returns the client for the
// call's environment. The store is not touched before all three pass. The
// confirmation is checked first, as it was before the key policy existed.
func (s *Server) authorizeWrite(st *callState, tool, key string) (*skret.Client, string, error) {
	st.keys = []string{key}
	if !argConfirm(st.args) {
		return nil, "", confirmErr(tool)
	}
	if err := s.authorize(st, key); err != nil {
		return nil, st.env, err
	}
	return s.clientFor(st.env)
}

// auditRead appends one mcp_read entry to the local provider's audit trail
// when the selected environment uses the local provider (only it maintains
// a file trail; cloud providers record access through their own audit
// systems). A trail failure fails the tool call loudly: a silently dropped
// audit line is exactly what the trail exists to prevent.
func (s *Server) auditRead(c *skret.Client, env, keyName string) error {
	resolved := c.Config()
	if resolved == nil || resolved.Provider != "local" || resolved.File == "" {
		return nil
	}
	entry := local.AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Op:        local.AuditOpMCPRead,
		KeyNames:  []string{keyName},
		Env:       env,
		Actor:     local.AuditActor(),
	}
	if err := local.AppendAuditEntry(local.AuditLogPathFor(resolved), entry); err != nil {
		slog.Error("skret-mcp: audit append failed", "env", s.redact(env), "err", s.redact(err.Error()))
		return err
	}
	return nil
}

// mustJSON marshals v; the status/env/list payloads are plain data and
// cannot fail. A failure returns an empty object rather than panicking.
func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("skret-mcp: marshal payload", "err", err)
		return "{}"
	}
	return string(data)
}
