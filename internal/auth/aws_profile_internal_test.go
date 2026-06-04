package auth

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSProfileFlow_List_ParseError(t *testing.T) {
	dir := t.TempDir()
	flow := &AWSProfileFlow{
		configPath: func() string {
			return dir
		},
	}
	_, err := flow.List()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws profile: parse")
}

func TestAWSProfileFlow_List_StatError(t *testing.T) {
	flow := &AWSProfileFlow{
		configPath: func() string {
			return "/nonexistent/path/that/should/fail/stat"
		},
	}
	_, err := flow.List()
	require.Error(t, err)
}

func TestAWSProfileFlow_HomeDirError(t *testing.T) {
	oldUserHomeDir := userHomeDir
	defer func() { userHomeDir = oldUserHomeDir }()

	userHomeDir = func() (string, error) {
		return "", errors.New("home error")
	}

	path := awsConfigPath()
	assert.Equal(t, "", path)

	flow := NewAWSProfileFlow()
	_, err := flow.List()
	require.Error(t, err)
}

func TestAWSProfileFlow_Login_ReloadError(t *testing.T) {
	dir := t.TempDir()
	configFile := dir + "/config"
	err := os.WriteFile(configFile, []byte("[default]\nregion=us-east-1\n"), 0644)
	require.NoError(t, err)

	count := 0
	flow := &AWSProfileFlow{
		configPath: func() string {
			count++
			if count == 2 {
				return dir // Second call in Login (the reload)
			}
			return configFile
		},
	}

	_, err = flow.Login(context.Background(), map[string]string{"profile": "default"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws profile: reload")
}
