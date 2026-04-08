package config_test

import (
	"testing"

	"github.com/n24q02m/skret/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConfig_UnmarshalYAML(t *testing.T) {
	raw := `
version: "1"
default_env: prod
project: knowledgeprism
environments:
  prod:
    provider: aws
    path: /knowledgeprism/prod
    region: ap-southeast-1
  dev:
    provider: local
    file: ./.secrets.dev.yaml
required:
  - DATABASE_URL
  - REDIS_URL
exclude:
  - GITHUB_TOKEN
`
	var cfg config.Config
	err := yaml.Unmarshal([]byte(raw), &cfg)
	require.NoError(t, err)

	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "prod", cfg.DefaultEnv)
	assert.Equal(t, "knowledgeprism", cfg.Project)
	assert.Len(t, cfg.Environments, 2)

	prod := cfg.Environments["prod"]
	assert.Equal(t, "aws", prod.Provider)
	assert.Equal(t, "/knowledgeprism/prod", prod.Path)
	assert.Equal(t, "ap-southeast-1", prod.Region)

	dev := cfg.Environments["dev"]
	assert.Equal(t, "local", dev.Provider)
	assert.Equal(t, "./.secrets.dev.yaml", dev.File)

	assert.Equal(t, []string{"DATABASE_URL", "REDIS_URL"}, cfg.Required)
	assert.Equal(t, []string{"GITHUB_TOKEN"}, cfg.Exclude)
}

func TestConfig_Validate_MissingVersion(t *testing.T) {
	cfg := config.Config{DefaultEnv: "prod"}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "version")
}

func TestConfig_Validate_MissingEnvironments(t *testing.T) {
	cfg := config.Config{Version: "1", DefaultEnv: "prod"}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "environments")
}

func TestConfig_Validate_DefaultEnvNotInEnvironments(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "staging",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/p/prod"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "staging")
}

func TestConfig_Validate_EnvironmentMissingProvider(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Path: "/p/prod"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "provider")
}

func TestConfig_Validate_AWSMissingPath(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "path")
}

func TestConfig_Validate_LocalMissingFile(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "dev",
		Environments: map[string]config.Environment{
			"dev": {Provider: "local"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "file")
}

func TestConfig_Validate_Success(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Project:    "myapp",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/myapp/prod", Region: "us-east-1"},
			"dev":  {Provider: "local", File: "./.secrets.dev.yaml"},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfig_Validate_UnsupportedVersion(t *testing.T) {
	cfg := config.Config{
		Version:    "99",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/p/prod"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "unsupported version")
}

func TestConfig_Validate_UnknownProvider(t *testing.T) {
	cfg := config.Config{
		Version:    "1",
		DefaultEnv: "prod",
		Environments: map[string]config.Environment{
			"prod": {Provider: "gcp", Path: "/p/prod"},
		},
	}
	err := cfg.Validate()
	assert.ErrorContains(t, err, "unknown provider")
}

func TestConfig_Validate_NoDefaultEnv(t *testing.T) {
	cfg := config.Config{
		Version: "1",
		Environments: map[string]config.Environment{
			"prod": {Provider: "aws", Path: "/p/prod"},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}
