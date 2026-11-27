package config_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mcpBaseConfig = `version: "1"
environments:
  dev:
    provider: local
    file: secrets.dev.yaml
  prod:
    provider: aws
    path: /app/prod
`

// TestMCPConfig_LoadDecodesBlock proves the mcp block decodes from yaml and
// passes validation when every allowed_envs entry names a declared
// environment.
func TestMCPConfig_LoadDecodesBlock(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allow_write: true
  allowed_envs:
    - dev
    - prod
`))
	require.NoError(t, err)
	require.NotNil(t, cfg.MCP)
	assert.True(t, cfg.MCP.AllowWrite)
	assert.Equal(t, []string{"dev", "prod"}, cfg.MCP.AllowedEnvs)
}

// TestMCPConfig_AbsentIsNil keeps the mcp block optional: a config without
// it loads with MCP left nil so the server applies its read-only defaults.
func TestMCPConfig_AbsentIsNil(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, mcpBaseConfig))
	require.NoError(t, err)
	assert.Nil(t, cfg.MCP)
}

// TestMCPConfig_EmptyAllowedEnvsMeansAll accepts an mcp block that only sets
// allow_write: an empty allowed_envs is the "every environment" default, not
// a validation error.
func TestMCPConfig_EmptyAllowedEnvsMeansAll(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allow_write: false
`))
	require.NoError(t, err)
	require.NotNil(t, cfg.MCP)
	assert.False(t, cfg.MCP.AllowWrite)
	assert.Empty(t, cfg.MCP.AllowedEnvs)
}

// TestMCPConfig_RejectsUndeclaredAllowedEnv guards the typo case the
// validator exists for: an allowed_envs entry that names no declared
// environment would silently lock the MCP server out, so Load must fail and
// name the offending entry.
func TestMCPConfig_RejectsUndeclaredAllowedEnv(t *testing.T) {
	_, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allowed_envs:
    - dev
    - prdo
`))
	require.Error(t, err)
	assert.Equal(t, `config: mcp.allowed_envs entry "prdo" not found in environments`, err.Error())
}

// TestConfig_Validate_MCPCheckedAfterNotify pins the Validate order on a
// struct built in code (no yaml): a valid notify block does not short-circuit
// the mcp check that follows it.
func TestConfig_Validate_MCPCheckedAfterNotify(t *testing.T) {
	cfg := &config.Config{
		Version:      "1",
		Environments: map[string]config.Environment{"dev": {Provider: "local", File: "s.yaml"}},
		Notify:       &config.NotifyConfig{WebhookURLs: config.WebhookURLs{"https://hooks.example.com/skret"}},
		MCP:          &config.MCPConfig{AllowedEnvs: []string{"staging"}},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `mcp.allowed_envs entry "staging" not found`)

	cfg.MCP.AllowedEnvs = []string{"dev"}
	assert.NoError(t, cfg.Validate())
}

// TestMCPConfig_DecodesPolicyFields proves the tool/key policy and the audit
// sink decode from yaml and pass validation when every entry is well formed.
func TestMCPConfig_DecodesPolicyFields(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allowed_tools: [skret_list, skret_get]
  allowed_keys: ["DB_*", API_KEY]
  denied_keys: ["*_ADMIN"]
  audit_log: logs/mcp-audit.log
`))
	require.NoError(t, err)
	require.NotNil(t, cfg.MCP)
	assert.Equal(t, []string{"skret_list", "skret_get"}, cfg.MCP.AllowedTools)
	assert.Equal(t, []string{"DB_*", "API_KEY"}, cfg.MCP.AllowedKeys)
	assert.Equal(t, []string{"*_ADMIN"}, cfg.MCP.DeniedKeys)
	assert.Equal(t, "logs/mcp-audit.log", cfg.MCP.AuditLog)
}

// TestMCPConfig_EmptyPolicyListsAreAccepted keeps explicit empty lists
// equivalent to omitting the fields.
func TestMCPConfig_EmptyPolicyListsAreAccepted(t *testing.T) {
	cfg, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allowed_tools: []
  allowed_keys: []
  denied_keys: []
`))
	require.NoError(t, err)
	require.NotNil(t, cfg.MCP)
	assert.Empty(t, cfg.MCP.AllowedTools)
	assert.Empty(t, cfg.MCP.AllowedKeys)
	assert.Empty(t, cfg.MCP.DeniedKeys)
}

// TestMCPConfig_RejectsUnknownTool fails closed on a tool name typo: an
// allowlist entry that names no tool would otherwise silently hide the tool
// the operator meant to allow.
func TestMCPConfig_RejectsUnknownTool(t *testing.T) {
	_, err := config.Load(writeTempConfig(t, mcpBaseConfig+`mcp:
  allowed_tools: [skret_list, skret_explode]
`))
	require.Error(t, err)
	assert.Equal(t, `config: mcp.allowed_tools entry "skret_explode" is not a known tool `+
		`(known: skret_list, skret_get, skret_env, skret_status, skret_doctor, skret_set, skret_delete, skret_rotate)`, err.Error())
}

// TestMCPConfig_RejectsInvalidKeyPatterns rejects key filters path.Match
// cannot evaluate, naming the field and the entry.
func TestMCPConfig_RejectsInvalidKeyPatterns(t *testing.T) {
	for _, tc := range []struct {
		name, block, want string
	}{
		{"allowed_keys bad glob", "  allowed_keys: [\"DB_[\"]\n", `config: mcp.allowed_keys entry "DB_[" is not a valid glob pattern: syntax error in pattern`},
		{"denied_keys bad glob", "  denied_keys: [\"[a-\"]\n", `config: mcp.denied_keys entry "[a-" is not a valid glob pattern: syntax error in pattern`},
		{"allowed_keys empty entry", "  allowed_keys: [\"API_KEY\", \" \"]\n", `config: mcp.allowed_keys has an empty entry`},
		{"denied_keys empty entry", "  denied_keys: [\"\"]\n", `config: mcp.denied_keys has an empty entry`},
		{"allowed_tools empty entry", "  allowed_tools: [\"\"]\n", `config: mcp.allowed_tools has an empty entry`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(writeTempConfig(t, mcpBaseConfig+"mcp:\n"+tc.block))
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
		})
	}
}

// TestMCPToolNames pins the closed tool set the allowlist is validated
// against, in tools/list order, and hands out a copy.
func TestMCPToolNames(t *testing.T) {
	names := config.MCPToolNames()
	assert.Equal(t, []string{"skret_list", "skret_get", "skret_env", "skret_status", "skret_doctor", "skret_set", "skret_delete", "skret_rotate"}, names)
	names[0] = "mutated"
	assert.Equal(t, "skret_list", config.MCPToolNames()[0], "callers must not be able to mutate the closed set")
	assert.True(t, config.ValidMCPTool("skret_get"))
	assert.False(t, config.ValidMCPTool("skret_explode"))
}
