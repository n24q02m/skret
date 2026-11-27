package mcp

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/n24q02m/skret/pkg/skret"
)

// Deny reasons recorded in the audit trail. The set is closed so an
// operator can alert on exact values.
const (
	reasonUnknownTool      = "unknown_tool"
	reasonInvalidParams    = "invalid_params"
	reasonToolNotAllowed   = "tool_not_allowed"
	reasonWriteDisabled    = "write_disabled"
	reasonEnvNotAllowed    = "env_not_allowed"
	reasonEnvUnknown       = "env_unknown"
	reasonKeyDenied        = "key_denied"
	reasonKeyNotAllowed    = "key_not_allowed"
	reasonInvalidArguments = "invalid_arguments"
	reasonConfirmRequired  = "confirm_required"
)

// denial is a tool call refused before any provider access, by the MCP
// policy or because of its own arguments. reason is the audit deny reason;
// err carries the message and remediation shown to the caller.
type denial struct {
	reason string
	err    error
}

func (d *denial) Error() string { return d.err.Error() }
func (d *denial) Unwrap() error { return d.err }

func deny(reason string, err error) error { return &denial{reason: reason, err: err} }

// denyReason returns the deny reason carried by err, or "" when err is not
// a refusal (a provider or audit failure of an allowed call).
func denyReason(err error) string {
	var d *denial
	if errors.As(err, &d) {
		return d.reason
	}
	return ""
}

// writeTools are the mutating tools gated by mcp.allow_write.
var writeTools = []string{"skret_set", "skret_delete", "skret_rotate"}

func isWriteTool(name string) bool { return slices.Contains(writeTools, name) }

// toolAllowed reports whether mcp.allowed_tools admits name. An empty
// allowlist admits every tool.
func (s *Server) toolAllowed(name string) bool {
	if s.cfg.MCP == nil || len(s.cfg.MCP.AllowedTools) == 0 {
		return true
	}
	return slices.Contains(s.cfg.MCP.AllowedTools, name)
}

// toolsPolicySet reports whether the operator set mcp.allowed_tools.
func (s *Server) toolsPolicySet() bool {
	return s.cfg.MCP != nil && len(s.cfg.MCP.AllowedTools) > 0
}

// toolVisible reports whether tools/list shows name. Without
// mcp.allowed_tools every tool is listed, as before the policy existed, and
// a disabled write tool is refused only on call. Once the operator sets
// mcp.allowed_tools, tools/list shows the tools a call can actually use:
// the allowlist, minus the write tools while mcp.allow_write is off.
func (s *Server) toolVisible(name string) bool {
	if !s.toolsPolicySet() {
		return true
	}
	return s.toolAllowed(name) && (!isWriteTool(name) || s.allowWrite())
}

// toolGate applies the tool-level policy to a known tool name.
func (s *Server) toolGate(name string) error {
	if !s.toolAllowed(name) {
		return deny(reasonToolNotAllowed, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, name+": tool is not permitted by mcp.allowed_tools for this skret-mcp server", nil),
			"ask the operator to add "+name+" to mcp.allowed_tools in .skret.yaml (then restart the server), or use a tool from tools/list"))
	}
	if isWriteTool(name) && !s.allowWrite() {
		return deny(reasonWriteDisabled, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, name+": write operations are disabled for this skret-mcp server", nil),
			"set mcp.allow_write: true in .skret.yaml (then restart the server) if the operator intends to allow secret mutation through MCP"))
	}
	return nil
}

// keyDecision applies mcp.denied_keys and mcp.allowed_keys to a key name
// and returns "" when the key is in scope, else the deny reason. A denied
// pattern always wins. Patterns are path.Match globs over the whole name;
// config validation rejects malformed ones, and should one reach here a
// malformed denied pattern denies every key while a malformed allowed
// pattern admits none (fail closed both ways).
func (s *Server) keyDecision(key string) string {
	if s.cfg.MCP == nil {
		return ""
	}
	if matchesAny(s.cfg.MCP.DeniedKeys, key, true) {
		return reasonKeyDenied
	}
	if len(s.cfg.MCP.AllowedKeys) > 0 && !matchesAny(s.cfg.MCP.AllowedKeys, key, false) {
		return reasonKeyNotAllowed
	}
	return ""
}

// matchesAny reports whether any pattern matches key; badPattern is the
// answer for a malformed pattern.
func matchesAny(patterns []string, key string, badPattern bool) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, key)
		if err != nil {
			if badPattern {
				return true
			}
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

// checkKey turns a key decision into the caller-facing refusal.
func (s *Server) checkKey(key string) error {
	switch s.keyDecision(key) {
	case reasonKeyDenied:
		return deny(reasonKeyDenied, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, fmt.Sprintf("key %q is denied by mcp.denied_keys", key), nil),
			"the operator excluded this key from MCP access; it cannot be read or changed through this server"))
	case reasonKeyNotAllowed:
		return deny(reasonKeyNotAllowed, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, fmt.Sprintf("key %q is not permitted by mcp.allowed_keys", key), nil),
			"ask the operator to add a matching pattern to mcp.allowed_keys in .skret.yaml (then restart the server); skret_list shows the keys in scope"))
	}
	return nil
}

// resolveEnv picks the environment of a tool call (the argument overrides
// the server default) and applies mcp.allowed_envs. It never touches a
// provider.
func (s *Server) resolveEnv(argEnv string) (string, error) {
	env := argEnv
	if env == "" {
		env = s.defaultEnv()
	}
	if env == "" {
		return "", deny(reasonEnvUnknown, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, "no environment selected", nil),
			"pass an env argument, set default_env in .skret.yaml, or start skret-mcp with --env"))
	}
	if !s.envAllowed(env) {
		return env, deny(reasonEnvNotAllowed, skret.WithRemediation(
			skret.NewError(skret.ExitConfigError, fmt.Sprintf("environment %q is not permitted by mcp.allowed_envs", env), nil),
			"ask the operator to add "+env+" to mcp.allowed_envs in .skret.yaml, or use one of: "+strings.Join(s.allowedEnvs(), ", ")))
	}
	if _, ok := s.cfg.Environments[env]; !ok {
		return env, deny(reasonEnvUnknown, skret.WithRemediation(
			skret.NewError(skret.ExitNotFoundError, fmt.Sprintf("environment %q not found in config", env), nil),
			"declared environments: "+strings.Join(s.envNames(), ", ")))
	}
	return env, nil
}

// authorize resolves the call's environment and applies the key policy to
// keys, recording both on st for the audit trail. It touches no provider,
// so a refused key that exists and one that does not answer alike.
func (s *Server) authorize(st *callState, keys ...string) error {
	env, err := s.resolveEnv(argEnv(st.args))
	st.env = env
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.checkKey(k); err != nil {
			return err
		}
	}
	return nil
}
