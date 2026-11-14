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
