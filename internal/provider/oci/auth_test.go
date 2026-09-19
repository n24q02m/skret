package oci

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAuthProvider is a minimal common.ConfigurationProvider for tests.
type stubAuthProvider struct {
	region string
}

func (s stubAuthProvider) TenancyOCID() (string, error)    { return "ocid1.tenancy.oc1..stub", nil }
func (s stubAuthProvider) UserOCID() (string, error)       { return "ocid1.user.oc1..stub", nil }
func (s stubAuthProvider) KeyFingerprint() (string, error) { return "aa:bb:cc:dd", nil }
func (s stubAuthProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return nil, errors.New("stub: no key")
}

func (s stubAuthProvider) KeyID() (string, error) {
	return "ocid1.tenancy.oc1..stub/ocid1.user.oc1..stub/aa:bb:cc:dd", nil
}

func (s stubAuthProvider) Region() (string, error) {
	if s.region == "" {
		return "", errors.New("stub: no region")
	}
	return s.region, nil
}

func (s stubAuthProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{AuthType: common.UnknownAuthenticationType}, nil
}

func TestResolveConfigurationProviderInstancePrincipal(t *testing.T) {
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		if key == EnvAuth {
			return InstancePrincipalAuth, true
		}
		return "", false
	}
	var called int
	deps.newInstancePrincipal = func() (common.ConfigurationProvider, error) {
		called++
		return stubAuthProvider{region: "us-ashburn-1"}, nil
	}
	p, err := resolveConfigurationProvider(deps, "")
	require.NoError(t, err)
	assert.Equal(t, 1, called)
	region, rerr := p.Region()
	require.NoError(t, rerr)
	assert.Equal(t, "us-ashburn-1", region)
}

func TestResolveConfigurationProviderInstancePrincipalError(t *testing.T) {
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		if key == EnvAuth {
			return InstancePrincipalAuth, true
		}
		return "", false
	}
	deps.newInstancePrincipal = func() (common.ConfigurationProvider, error) {
		return nil, errors.New("metadata endpoint unreachable")
	}
	_, err := resolveConfigurationProvider(deps, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "instance principal auth")
}

func TestResolveConfigurationProviderEnvOverrides(t *testing.T) {
	keyPath := writeTestKeyFile(t)
	env := map[string]string{
		EnvUser:        "ocid1.user.oc1..env",
		EnvTenancy:     "ocid1.tenancy.oc1..env",
		EnvFingerprint: "11:22:33:44",
		EnvKeyFile:     keyPath,
		EnvRegion:      "ap-singapore-1",
	}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	deps.homeDir = func() (string, error) { return t.TempDir(), nil }
	p, err := resolveConfigurationProvider(deps, "")
	require.NoError(t, err)
	region, rerr := p.Region()
	require.NoError(t, rerr)
	assert.Equal(t, "ap-singapore-1", region)
	tenancy, terr := p.TenancyOCID()
	require.NoError(t, terr)
	assert.Equal(t, "ocid1.tenancy.oc1..env", tenancy)
}

func TestResolveConfigurationProviderEnvOverridesMissingKeyFile(t *testing.T) {
	env := map[string]string{
		EnvUser:        "ocid1.user.oc1..env",
		EnvTenancy:     "ocid1.tenancy.oc1..env",
		EnvFingerprint: "11:22:33:44",
		EnvKeyFile:     "",
	}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	_, ok, err := envConfigurationProvider(deps)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestResolveConfigurationProviderEnvOverridesUnreadableKeyFile(t *testing.T) {
	env := map[string]string{
		EnvUser:        "ocid1.user.oc1..env",
		EnvTenancy:     "ocid1.tenancy.oc1..env",
		EnvFingerprint: "11:22:33:44",
		EnvKeyFile:     "Z:/definitely/not/a/real/path.pem",
	}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	_, err := resolveConfigurationProvider(deps, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), EnvKeyFile)
}

func TestResolveConfigurationProviderConfigFile(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".oci"), 0o700))
	require.NoError(t, writeFile(filepath.Join(home, ".oci", "config"), stubOCIConfigFile))
	deps := defaultAuthDeps()
	deps.lookupEnv = func(string) (string, bool) { return "", false }
	deps.homeDir = func() (string, error) { return home, nil }
	p, err := resolveConfigurationProvider(deps, "")
	require.NoError(t, err)
	require.NotNil(t, p)
	region, rerr := p.Region()
	require.NoError(t, rerr)
	assert.Equal(t, "us-ashburn-1", region)
}

func TestResolveConfigurationProviderConfigFileCustomPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "custom-config")
	require.NoError(t, writeFile(cfgPath, stubOCIConfigFile))
	env := map[string]string{EnvConfigFile: cfgPath}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
	p, err := resolveConfigurationProvider(deps, "")
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestResolveConfigurationProviderNone(t *testing.T) {
	deps := defaultAuthDeps()
	deps.lookupEnv = func(string) (string, bool) { return "", false }
	deps.homeDir = func() (string, error) { return t.TempDir(), nil }
	_, err := resolveConfigurationProvider(deps, "")
	require.Error(t, err)
	for _, want := range []string{"oci setup config", EnvAuth} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestResolveConfigurationProviderComposesEnvOverFile(t *testing.T) {
	keyPath := writeTestKeyFile(t)
	home := t.TempDir()
	env := map[string]string{
		EnvUser:        "ocid1.user.oc1..env",
		EnvTenancy:     "ocid1.tenancy.oc1..env",
		EnvFingerprint: "11:22:33:44",
		EnvKeyFile:     keyPath,
	}
	deps := defaultAuthDeps()
	deps.lookupEnv = func(key string) (string, bool) {
		if v, ok := env[key]; ok {
			return v, ok
		}
		return "", false
	}
	deps.homeDir = func() (string, error) { return home, nil }
	p, err := resolveConfigurationProvider(deps, "PROD")
	require.NoError(t, err)
	tenancy, terr := p.TenancyOCID()
	require.NoError(t, terr)
	assert.Equal(t, "ocid1.tenancy.oc1..env", tenancy)
}

// stubOCIConfigFile is a minimal OCI CLI config file for path-presence tests.
const stubOCIConfigFile = "[DEFAULT]\n" +
	"user=ocid1.user.oc1..file\n" +
	"fingerprint=aa:bb:cc:dd\n" +
	"tenancy=ocid1.tenancy.oc1..file\n" +
	"region=us-ashburn-1\n" +
	"key_file=~/.oci/oci_api_key.pem\n"

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// writeTestKeyFile generates an in-memory RSA key and writes it as PEM so
// RawConfigurationProvider can parse it without touching the network.
func writeTestKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	path := filepath.Join(t.TempDir(), "test_key.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}
