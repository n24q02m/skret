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
type toolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
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
// hint when one is attached, so an agent sees the copy-pasteable fix.
func toolErr(err error) toolResult {
	msg := err.Error()
	if hint := skret.RemediationOf(err); hint != "" {
		msg += "\nremediation: " + hint
	}
	return toolResult{Content: []content{{Type: "text", Text: msg}}, IsError: true}
}

// writeGateErr is the policy result for every write tool while
// mcp.allow_write is false.
func writeGateErr(tool string) toolResult {
	return toolResult{
		Content: []content{{Type: "text", Text: fmt.Sprintf(
			"%s: write operations are disabled for this skret-mcp server\nremediation: set mcp.allow_write: true in .skret.yaml (then restart the server) if the operator intends to allow secret mutation through MCP", tool)}},
		IsError: true,
	}
}

// argErr builds the standard missing/wrong-typed argument result.
func argErr(tool, argsShape string) toolResult {
	return toolErr(skret.WithRemediation(
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
		`"env":{"type":"string","description":"Target environment name; defaults to the server's resolved environment."}` +
		`},"required":["key","value"]}`
)

// tools lists every exposed tool. Write tools are always listed (clients
// must be able to discover them); calling one while gated returns the
// write-gate error result.
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
			Description: "Create or update a skret secret. Requires mcp.allow_write: true in .skret.yaml (default off).",
			InputSchema: json.RawMessage(schemaSet),
		},
		{
			Name:        "skret_delete",
			Description: "Delete a skret secret. Requires mcp.allow_write: true in .skret.yaml (default off).",
			InputSchema: json.RawMessage(schemaGet),
		},
		{
			Name:        "skret_rotate",
			Description: "Replace a skret secret's value with an explicit new value (recorded as a rotation in the audit trail). Requires mcp.allow_write: true in .skret.yaml (default off).",
			InputSchema: json.RawMessage(schemaSet),
		},
	}
}

// listToolsResult shapes the tools/list response.
func listToolsResult() map[string]any {
	return map[string]any{"tools": tools()}
}

// callParams is the tools/call request params.
type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// toolsCall dispatches a tools/call. Structural failures (unknown tool,
// malformed arguments) are protocol errors; execution outcomes (including
// policy denial and missing keys) are isError results per the MCP spec.
func (s *Server) toolsCall(params json.RawMessage) (any, *rpcError) {
	var p callParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: " + err.Error()}
		}
	}
	if p.Name == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "invalid params: name is required"}
	}
	args := p.Arguments
	if args == nil {
		args = map[string]any{}
	}

	switch p.Name {
	case "skret_list":
		return s.toolList(args), nil
	case "skret_get":
		return s.toolGet(args), nil
	case "skret_env":
		return s.toolEnvs(), nil
	case "skret_status", "skret_doctor":
		return s.toolStatus(), nil
	case "skret_set":
		return s.toolSet(args), nil
	case "skret_delete":
		return s.toolDelete(args), nil
	case "skret_rotate":
		return s.toolRotate(args), nil
	default:
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown tool: " + p.Name}
	}
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

// toolList returns the key names (never values) for the selected
// environment. The list read is audited like skret_get so the trail shows
// every MCP access scope.
func (s *Server) toolList(args map[string]any) toolResult {
	c, env, err := s.clientFor(argEnv(args))
	if err != nil {
		return toolErr(err)
	}
	secrets, err := c.List(context.Background())
	if err != nil {
		return toolErr(err)
	}
	names := make([]string, 0, len(secrets))
	for _, sec := range secrets {
		names = append(names, sec.Key)
	}
	if err := s.auditRead(c, env, "*"); err != nil {
		return toolErr(err)
	}
	return textResult(mustJSON(names))
}

// toolGet returns one secret's value -- the only path a value takes out of
// the server.
func (s *Server) toolGet(args map[string]any) toolResult {
	key, ok := argString(args, "key")
	if !ok {
		return argErr("skret_get", schemaGet)
	}
	c, env, err := s.clientFor(argEnv(args))
	if err != nil {
		return toolErr(err)
	}
	sec, err := c.Get(context.Background(), key)
	if err != nil {
		return toolErr(err)
	}
	if err := s.auditRead(c, env, key); err != nil {
		return toolErr(err)
	}
	return textResult(sec.Value)
}

// envList is the skret_env payload.
type envList struct {
	Environments []string `json:"environments"`
	DefaultEnv   string   `json:"default_env,omitempty"`
}

func (s *Server) toolEnvs() toolResult {
	return textResult(mustJSON(envList{Environments: s.allowedEnvs(), DefaultEnv: s.defaultEnv()}))
}

// statusReport is the skret_status / skret_doctor payload. It reflects
// configuration and policy only -- running it never touches a provider.
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
}

func (s *Server) toolStatus() toolResult {
	env := s.defaultEnv()
	providerName := ""
	var path string
	if e, ok := s.cfg.Environments[env]; ok {
		providerName = e.Provider
		path = e.Path
	}
	return textResult(mustJSON(statusReport{
		OK:          true,
		Version:     s.opts.Version,
		Env:         env,
		Provider:    providerName,
		Path:        path,
		ConfigFile:  s.cfgPath,
		AllowWrite:  s.allowWrite(),
		AllowedEnvs: s.allowedEnvs(),
		ReadOnly:    !s.allowWrite(),
	}))
}

// toolSet creates or updates a secret (write-gated).
func (s *Server) toolSet(args map[string]any) toolResult {
	const shape = `{"key": "<name>", "value": "<value>"}`
	if !s.allowWrite() {
		return writeGateErr("skret_set")
	}
	key, keyOK := argString(args, "key")
	value, valOK := argString(args, "value")
	if !keyOK || !valOK {
		return argErr("skret_set", shape)
	}
	c, env, err := s.clientFor(argEnv(args))
	if err != nil {
		return toolErr(err)
	}
	if err := c.Set(context.Background(), key, value, provider.SecretMeta{}); err != nil {
		return toolErr(err)
	}
	slog.Info("skret-mcp: set", "env", env, "key", key)
	return textResult(fmt.Sprintf("set %s (env %s)", key, env))
}

// toolDelete removes a secret (write-gated).
func (s *Server) toolDelete(args map[string]any) toolResult {
	const shape = `{"key": "<name>"}`
	if !s.allowWrite() {
		return writeGateErr("skret_delete")
	}
	key, ok := argString(args, "key")
	if !ok {
		return argErr("skret_delete", shape)
	}
	c, env, err := s.clientFor(argEnv(args))
	if err != nil {
		return toolErr(err)
	}
	if err := c.Delete(context.Background(), key); err != nil {
		return toolErr(err)
	}
	slog.Info("skret-mcp: delete", "env", env, "key", key)
	return textResult(fmt.Sprintf("deleted %s (env %s)", key, env))
}

// toolRotate replaces a secret's value, recorded as a rotation in the
// local provider's audit trail (write-gated). Generation stays with the
// caller: MCP passes the explicit replacement value, exactly like
// `skret rotate --value`.
func (s *Server) toolRotate(args map[string]any) toolResult {
	const shape = `{"key": "<name>", "value": "<new value>"}`
	if !s.allowWrite() {
		return writeGateErr("skret_rotate")
	}
	key, keyOK := argString(args, "key")
	value, valOK := argString(args, "value")
	if !keyOK || !valOK {
		return argErr("skret_rotate", shape)
	}
	c, env, err := s.clientFor(argEnv(args))
	if err != nil {
		return toolErr(err)
	}
	ctx := local.WithAuditOp(context.Background(), local.AuditOpRotate)
	if err := c.Set(ctx, key, value, provider.SecretMeta{}); err != nil {
		return toolErr(err)
	}
	slog.Info("skret-mcp: rotate", "env", env, "key", key)
	return textResult(fmt.Sprintf("rotated %s (env %s)", key, env))
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
		slog.Error("skret-mcp: audit append failed", "env", env, "err", err)
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
